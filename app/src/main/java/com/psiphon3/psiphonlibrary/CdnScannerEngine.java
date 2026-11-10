package com.psiphon3.psiphonlibrary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * DARKNET CDN scanner engine (port of the "CDN IP Scanner v3" web tool).
 * Each IP is tested several times with TCP + TLS (SNI) + a real HTTP request,
 * the CDN is detected from response headers, and results are scored by
 * latency + jitter + packet loss. Optional download speed test for the best IPs.
 */
public class CdnScannerEngine {

    // ───────── public API types ─────────

    public interface Listener {
        void onInit(int total, String space);
        void onProgress(int done, int total, String currentIp, int lastPingMs);
        void onResult(Result result);
        void onPhase(String text);
        void onSpeed(String ip, int port, double mbps);
        void onFinished(List<Result> sorted, boolean stopped);
        void onError(String message);
    }

    public static class Result {
        public String ip;
        public int port;
        public int ok;
        public int tries;
        public int loss;
        public int ping;      // avg TCP connect ms
        public int tls;       // avg TLS handshake ms
        public int ttfb;      // avg time to first byte ms
        public int total;     // avg tcp+tls+ttfb ms
        public int jitter;
        public int status;
        public String provider = "";
        public String colo = "";
        public String server = "";
        public int score;
        public volatile double mbps = -1; // -1 = not measured
    }

    /** Scan settings; defaults mirror the web tool (a bit lighter for phones). */
    public static class Settings {
        public int tries = 3;
        public int minOk = 2;
        public int threads = 100;
        public double timeout = 3.0;
        public String ports = "443";
        public int maxIps = 1000;
        public String sni = "speed.cloudflare.com";
        public String host = "speed.cloudflare.com";
        public String path = "/cdn-cgi/trace";
        public boolean head = false;
        public String expectProvider = "";
        public String statuses = "200";
        public String sortBy = "score"; // score | ping | speed
        public boolean verify = true;
        public boolean speed = false;
        public int speedTop = 5;
        public String speedPath = "/__down?bytes=3000000";
        public int maxTotal = 0;
        public int maxJitter = 0;
        public String colos = "";
        public String exclude = "";
        public String ipver = "4"; // 4 | 6 | both

        /** Same presets as the web tool's provider selector. */
        public void applyPreset(String provider) {
            switch (provider) {
                case "cloudflare":
                    sni = "speed.cloudflare.com"; host = "speed.cloudflare.com";
                    path = "/cdn-cgi/trace"; speedPath = "/__down?bytes=3000000";
                    expectProvider = ""; statuses = "200";
                    break;
                case "fastly":
                    sni = "www.fastly.com"; host = "www.fastly.com";
                    path = "/"; speedPath = "/"; expectProvider = ""; statuses = "";
                    break;
                case "akamai":
                    sni = "www.akamai.com"; host = "www.akamai.com";
                    path = "/"; speedPath = "/"; expectProvider = ""; statuses = "";
                    break;
                default:
                    expectProvider = "";
                    break;
            }
        }
    }

    /** What to scan. mode: "preset" | "list" | "range". */
    public static class Input {
        public String mode = "preset";
        public String provider = "cloudflare"; // cloudflare | fastly | akamai | custom
        public String customRanges = "";
        public String listText = "";
        public String startIp = "";
        public String endIp = "";
    }

    // ───────── provider ranges ─────────

    private static final Pattern IPV4_LIT = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");
    private static final Pattern DOMAIN = Pattern.compile("(?=.{4,253}$)([A-Za-z0-9-]{1,63}\\.)+[A-Za-z]{2,}");

    private static final Map<String, String[]> FALLBACK = new HashMap<>();
    private static final Map<String, String[]> V6_FALLBACK = new HashMap<>();
    private static final Map<String, Object[]> CACHE = new HashMap<>();

    static {
        FALLBACK.put("cloudflare", new String[]{
                "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
                "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
                "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"});
        FALLBACK.put("fastly", new String[]{
                "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "104.156.80.0/20",
                "140.248.64.0/18", "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
                "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"});
        FALLBACK.put("akamai", new String[]{
                "2.16.0.0/13", "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "23.192.0.0/11"});
        V6_FALLBACK.put("cloudflare", new String[]{
                "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
                "2a06:98c0::/29", "2c0f:f248::/32"});
        V6_FALLBACK.put("fastly", new String[]{"2a04:4e40::/32", "2a04:4e42::/32"});
    }

    private static String httpGet(String url) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);
        InputStream in = c.getInputStream();
        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0 && bo.size() < 1024 * 1024) bo.write(b, 0, n);
            return bo.toString("UTF-8");
        } finally {
            in.close();
        }
    }

    /** Official live list when reachable, otherwise the built-in fallback (cached 10 min). */
    @SuppressWarnings("unchecked")
    static synchronized List<String> providerRanges(String key) {
        Object[] hit = CACHE.get(key);
        if (hit != null && System.currentTimeMillis() - (Long) hit[0] < 600000L) {
            return (List<String>) hit[1];
        }
        List<String> out = new ArrayList<>();
        try {
            if ("cloudflare".equals(key)) {
                out.addAll(splitWs(httpGet("https://www.cloudflare.com/ips-v4")));
                out.addAll(splitWs(httpGet("https://www.cloudflare.com/ips-v6")));
            } else if ("fastly".equals(key)) {
                // JSON {"addresses":[...],"ipv6_addresses":[...]} – pull every CIDR out of it
                Matcher m = Pattern.compile("[0-9a-fA-F:.]+/\\d{1,3}").matcher(httpGet("https://api.fastly.com/public-ip-list"));
                while (m.find()) out.add(m.group());
            }
        } catch (Exception e) {
            out.clear();
        }
        if (out.isEmpty()) {
            String[] f = FALLBACK.get(key);
            if (f != null) Collections.addAll(out, f);
            String[] f6 = V6_FALLBACK.get(key);
            if (f6 != null) Collections.addAll(out, f6);
        }
        CACHE.put(key, new Object[]{System.currentTimeMillis(), out});
        return out;
    }

    private static List<String> splitWs(String s) {
        List<String> r = new ArrayList<>();
        for (String t : s.split("\\s+")) if (!t.isEmpty()) r.add(t);
        return r;
    }

    // ───────── targets: parse / subtract / sample ─────────

    private static class Iv {
        final int ver;
        final BigInteger a;
        final BigInteger b;

        Iv(int ver, BigInteger a, BigInteger b) {
            this.ver = ver;
            this.a = a;
            this.b = b;
        }
    }

    /** Literal IPv4/IPv6 -> bytes, or null (never does a DNS lookup). */
    private static byte[] parseIp(String s) {
        try {
            if (s.indexOf(':') >= 0) {
                if (!s.matches("[0-9a-fA-F:.]+")) return null;
            } else {
                if (!IPV4_LIT.matcher(s).matches()) return null;
                for (String p : s.split("\\.")) if (Integer.parseInt(p) > 255) return null;
            }
            return InetAddress.getByName(s).getAddress();
        } catch (Exception e) {
            return null;
        }
    }

    private static int verOf(byte[] b) {
        return b.length == 4 ? 4 : 6;
    }

    private static List<Iv> parseTargets(String text) {
        List<Iv> ivs = new ArrayList<>();
        if (text == null) return ivs;
        for (String tok : text.split("[\\s,;]+")) {
            if (tok.isEmpty()) continue;
            try {
                if (tok.contains("/")) {
                    String[] p = tok.split("/", 2);
                    byte[] ip = parseIp(p[0]);
                    if (ip == null) continue;
                    int bits = ip.length * 8;
                    int prefix = Integer.parseInt(p[1].trim());
                    if (prefix < 0 || prefix > bits) continue;
                    int host = bits - prefix;
                    BigInteger a = new BigInteger(1, ip).shiftRight(host).shiftLeft(host);
                    BigInteger b = a.add(BigInteger.ONE.shiftLeft(host)).subtract(BigInteger.ONE);
                    ivs.add(new Iv(verOf(ip), a, b));
                } else if (tok.contains("-")) {
                    String[] p = tok.split("-", 2);
                    byte[] ip = parseIp(p[0]);
                    if (ip == null) continue;
                    BigInteger a = new BigInteger(1, ip);
                    BigInteger b;
                    if (p[1].contains(".") || p[1].contains(":")) {
                        byte[] ip2 = parseIp(p[1]);
                        if (ip2 == null || ip2.length != ip.length) continue;
                        b = new BigInteger(1, ip2);
                    } else {
                        BigInteger low = BigInteger.valueOf(Long.parseLong(p[1].trim()));
                        b = a.andNot(BigInteger.valueOf(255)).or(low);
                    }
                    if (b.compareTo(a) >= 0) ivs.add(new Iv(verOf(ip), a, b));
                } else {
                    byte[] ip = parseIp(tok);
                    if (ip == null) continue;
                    BigInteger a = new BigInteger(1, ip);
                    ivs.add(new Iv(verOf(ip), a, a));
                }
            } catch (Exception ignored) {
            }
        }
        return ivs;
    }

    private static List<Iv> subtract(List<Iv> ivs, List<Iv> ex) {
        List<Iv> exs = new ArrayList<>(ex);
        Collections.sort(exs, (x, y) -> x.a.compareTo(y.a));
        List<Iv> out = new ArrayList<>();
        for (Iv iv : ivs) {
            BigInteger cur = iv.a;
            for (Iv e : exs) {
                if (e.ver != iv.ver || e.b.compareTo(cur) < 0 || e.a.compareTo(iv.b) > 0) continue;
                if (e.a.compareTo(cur) > 0) out.add(new Iv(iv.ver, cur, e.a.subtract(BigInteger.ONE)));
                cur = cur.max(e.b.add(BigInteger.ONE));
                if (cur.compareTo(iv.b) > 0) break;
            }
            if (cur.compareTo(iv.b) <= 0) out.add(new Iv(iv.ver, cur, iv.b));
        }
        return out;
    }

    private static BigInteger randomBelow(BigInteger n, Random rnd) {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), rnd);
        } while (r.compareTo(n) >= 0);
        return r;
    }

    private static String toIp(BigInteger v, int ver) {
        int len = ver == 4 ? 4 : 16;
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - copy, out, len - copy, copy);
        try {
            return InetAddress.getByAddress(out).getHostAddress();
        } catch (Exception e) {
            return null;
        }
    }

    /** Uniform random sample (merged ranges, proportional to size). Returns IPs; total space in out[0]. */
    private static List<String> pickVer(List<Iv> group, int limit, int ver, Random rnd, BigInteger[] totalOut) {
        List<Iv> sorted = new ArrayList<>(group);
        Collections.sort(sorted, (x, y) -> x.a.compareTo(y.a));
        List<BigInteger[]> merged = new ArrayList<>();
        for (Iv iv : sorted) {
            if (!merged.isEmpty() && iv.a.compareTo(merged.get(merged.size() - 1)[1].add(BigInteger.ONE)) <= 0) {
                BigInteger[] last = merged.get(merged.size() - 1);
                last[1] = last[1].max(iv.b);
            } else {
                merged.add(new BigInteger[]{iv.a, iv.b});
            }
        }
        BigInteger total = BigInteger.ZERO;
        for (BigInteger[] m : merged) total = total.add(m[1].subtract(m[0]).add(BigInteger.ONE));
        totalOut[0] = total;

        List<BigInteger> nums = new ArrayList<>();
        BigInteger lim = BigInteger.valueOf(limit);
        if (total.compareTo(lim) <= 0) {
            for (BigInteger[] m : merged) {
                for (BigInteger i = m[0]; i.compareTo(m[1]) <= 0; i = i.add(BigInteger.ONE)) nums.add(i);
            }
        } else {
            Set<BigInteger> set = new HashSet<>();
            for (BigInteger[] m : merged) {
                BigInteger size = m[1].subtract(m[0]).add(BigInteger.ONE);
                // k = min(size, max(1, round(limit * size / total)))
                BigInteger kb = lim.multiply(size).add(total.shiftRight(1)).divide(total);
                int k = kb.max(BigInteger.ONE).min(size).min(BigInteger.valueOf(limit)).intValue();
                if (size.compareTo(BigInteger.valueOf(k * 2L)) <= 0) {
                    List<BigInteger> all = new ArrayList<>();
                    for (BigInteger i = m[0]; i.compareTo(m[1]) <= 0; i = i.add(BigInteger.ONE)) all.add(i);
                    Collections.shuffle(all, rnd);
                    set.addAll(all.subList(0, Math.min(k, all.size())));
                } else {
                    int got = 0;
                    int guard = k * 6 + 30;
                    while (got < k && guard-- > 0) {
                        if (set.add(m[0].add(randomBelow(size, rnd)))) got++;
                    }
                }
            }
            nums.addAll(set);
        }
        Collections.shuffle(nums, rnd);
        List<String> ips = new ArrayList<>();
        for (BigInteger n : nums) {
            if (ips.size() >= limit) break;
            String s = toIp(n, ver);
            if (s != null) ips.add(s);
        }
        return ips;
    }

    private static boolean isGlobal(String ip) {
        byte[] b = parseIp(ip);
        if (b == null) return false;
        try {
            InetAddress a = InetAddress.getByAddress(b);
            if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                    || a.isSiteLocalAddress() || a.isMulticastAddress()) return false;
        } catch (Exception e) {
            return false;
        }
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        if (b.length == 4) {
            if (b0 == 100 && b1 >= 64 && b1 <= 127) return false;             // CGNAT
            if (b0 == 192 && b1 == 0 && (b[2] & 0xff) == 0) return false;      // 192.0.0.0/24
            if (b0 == 198 && (b1 == 18 || b1 == 19)) return false;             // benchmarking
            if (b0 >= 240) return false;                                       // reserved
            return true;
        }
        if ((b0 & 0xfe) == 0xfc) return false;                                 // fc00::/7
        if (b0 == 0x20 && b1 == 0x01 && b[2] == 0x0d && (b[3] & 0xff) == 0xb8) return false; // doc
        return true;
    }

    private static List<String> pick(List<Iv> ivs, int limit, String ver, Random rnd, BigInteger[] spaceOut) {
        List<Integer> want = new ArrayList<>();
        if ("6".equals(ver)) want.add(6);
        else if ("both".equals(ver)) { want.add(4); want.add(6); }
        else want.add(4);
        List<Integer> used = new ArrayList<>();
        Map<Integer, List<Iv>> groups = new LinkedHashMap<>();
        for (int v : want) {
            List<Iv> g = new ArrayList<>();
            for (Iv iv : ivs) if (iv.ver == v) g.add(iv);
            if (!g.isEmpty()) { groups.put(v, g); used.add(v); }
        }
        List<String> ips = new ArrayList<>();
        BigInteger total = BigInteger.ZERO;
        for (int v : used) {
            BigInteger[] t = new BigInteger[1];
            ips.addAll(pickVer(groups.get(v), Math.max(1, limit / used.size()), v, rnd, t));
            total = total.add(t[0]);
        }
        spaceOut[0] = total;
        Collections.shuffle(ips, rnd);
        List<String> out = new ArrayList<>();
        for (String ip : ips) if (isGlobal(ip)) out.add(ip);
        return out;
    }

    /** Resolve domains found in the list text (A and/or AAAA by IP version). */
    private static String expandDomains(String text, String ver) {
        StringBuilder sb = new StringBuilder(text == null ? "" : text).append('\n');
        if (text == null) return sb.toString();
        int count = 0;
        for (String tok : text.split("[\\s,;]+")) {
            if (!DOMAIN.matcher(tok).matches()) continue;
            try {
                for (InetAddress a : InetAddress.getAllByName(tok)) {
                    boolean v4 = a.getAddress().length == 4;
                    if (("4".equals(ver) && !v4) || ("6".equals(ver) && v4)) continue;
                    sb.append(a.getHostAddress()).append('\n');
                    count++;
                }
            } catch (Exception ignored) {
            }
            if (count > 500) break;
        }
        return sb.toString();
    }

    // ───────── probing ─────────

    private static class Run {
        double tcp, tls, ttfb;
        int status;
        String prov = "", colo = "", server = "";
    }

    private final Listener listener;
    private final AtomicBoolean stopFlag = new AtomicBoolean(false);
    private volatile ExecutorService pool;

    public CdnScannerEngine(Listener listener) {
        this.listener = listener;
    }

    public void stop() {
        stopFlag.set(true);
        ExecutorService p = pool;
        if (p != null) p.shutdownNow();
    }

    private static String[] detect(Map<String, String> h, String body) {
        String server = h.containsKey("server") ? h.get("server") : "";
        String via = h.containsKey("via") ? h.get("via").toLowerCase(Locale.ROOT) : "";
        String xServed = h.containsKey("x-served-by") ? h.get("x-served-by") : "";
        String xCache = h.containsKey("x-cache") ? h.get("x-cache").toLowerCase(Locale.ROOT) : "";
        String prov;
        if (h.containsKey("cf-ray") || "cloudflare".equals(server.toLowerCase(Locale.ROOT))) {
            prov = "cloudflare";
        } else if (h.containsKey("x-fastly-request-id") || via.contains("fastly") || xServed.contains("cache-")) {
            prov = "fastly";
        } else if (server.toLowerCase(Locale.ROOT).contains("akamai") || via.contains("akamai")
                || h.containsKey("akamai-grn") || xCache.contains("akamai") || anyKeyStarts(h, "x-akamai", "akamai")) {
            prov = "akamai";
        } else {
            String s = server.toLowerCase(Locale.ROOT);
            prov = s.isEmpty() ? "unknown" : s.substring(0, Math.min(20, s.length()));
        }
        String colo = "";
        Matcher m = Pattern.compile("colo=(\\w+)").matcher(body);
        if (m.find()) {
            colo = m.group(1);
        } else if (h.containsKey("cf-ray")) {
            String r = h.get("cf-ray");
            colo = r.substring(r.lastIndexOf('-') + 1);
        } else if (h.containsKey("x-served-by")) {
            String[] parts = xServed.split(",");
            String last = parts[parts.length - 1].trim();
            colo = last.substring(last.lastIndexOf('-') + 1);
        }
        return new String[]{prov, colo};
    }

    private static boolean anyKeyStarts(Map<String, String> h, String p1, String p2) {
        for (String k : h.keySet()) if (k.startsWith(p1) || k.startsWith(p2)) return true;
        return false;
    }

    private static SSLSocketFactory factory(boolean verify) throws Exception {
        if (verify) return (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] c, String a) { }
            @Override public void checkServerTrusted(X509Certificate[] c, String a) { }
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        return ctx.getSocketFactory();
    }

    private static SSLSocket wrapTls(Socket raw, SSLSocketFactory f, Settings s, int port) throws IOException {
        SSLSocket ssl = (SSLSocket) f.createSocket(raw, s.sni, port, true);
        if (android.os.Build.VERSION.SDK_INT >= 24) {
            try {
                SSLParameters p = ssl.getSSLParameters();
                p.setServerNames(Collections.singletonList(new SNIHostName(s.sni)));
                if (s.verify) p.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(p);
            } catch (Throwable ignored) {
            }
        }
        return ssl;
    }

    private Run probeOnce(String ip, int port, Settings s, SSLSocketFactory f) {
        int timeoutMs = (int) (s.timeout * 1000);
        long t0 = System.nanoTime();
        Socket raw = new Socket();
        SSLSocket tls = null;
        try {
            raw.connect(new InetSocketAddress(ip, port), timeoutMs);
            double tcp = (System.nanoTime() - t0) / 1e6;
            raw.setSoTimeout(timeoutMs);
            tls = wrapTls(raw, f, s, port);
            tls.setSoTimeout(timeoutMs);
            tls.startHandshake();
            double tlsMs = (System.nanoTime() - t0) / 1e6 - tcp;
            long t1 = System.nanoTime();
            String req = (s.head ? "HEAD " : "GET ") + s.path + " HTTP/1.1\r\nHost: " + s.host
                    + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            OutputStream out = tls.getOutputStream();
            out.write(req.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            ByteArrayOutputStream data = new ByteArrayOutputStream();
            double ttfb = -1;
            byte[] buf = new byte[4096];
            InputStream in = tls.getInputStream();
            try {
                while (data.size() < 16384) {
                    int n = in.read(buf);
                    if (ttfb < 0) ttfb = (System.nanoTime() - t1) / 1e6;
                    if (n <= 0) break;
                    data.write(buf, 0, n);
                }
            } catch (IOException e) {
                if (data.size() == 0) return null;
            }
            String all = new String(data.toByteArray(), StandardCharsets.ISO_8859_1);
            int cut = all.indexOf("\r\n\r\n");
            String head = cut >= 0 ? all.substring(0, cut) : all;
            String body = cut >= 0 ? all.substring(cut + 4) : "";
            String[] lines = head.split("\r\n");
            String[] first = lines[0].trim().split("\\s+");
            if (first.length < 2) return null;
            Run r = new Run();
            r.status = Integer.parseInt(first[1]);
            Map<String, String> h = new HashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int c = lines[i].indexOf(':');
                if (c > 0) h.put(lines[i].substring(0, c).trim().toLowerCase(Locale.ROOT), lines[i].substring(c + 1).trim());
            }
            String[] d = detect(h, new String(body.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8));
            r.tcp = tcp;
            r.tls = tlsMs;
            r.ttfb = Math.max(ttfb, 0);
            r.prov = d[0];
            r.colo = d[1];
            r.server = h.containsKey("server") ? h.get("server") : "";
            return r;
        } catch (Exception e) {
            return null;
        } finally {
            try { if (tls != null) tls.close(); } catch (IOException ignored) {}
            try { raw.close(); } catch (IOException ignored) {}
        }
    }

    private Result testIp(String ip, int port, Settings s, SSLSocketFactory f, Set<Integer> statuses, Set<String> colos) {
        List<Run> runs = new ArrayList<>();
        for (int i = 0; i < s.tries; i++) {
            if (stopFlag.get()) return null;
            Run r = probeOnce(ip, port, s, f);
            if (r != null) runs.add(r);
            if (i < s.tries - 1) {
                try { Thread.sleep(50); } catch (InterruptedException e) { return null; }
            }
        }
        if (runs.size() < Math.min(s.minOk, s.tries) || runs.isEmpty()) return null;
        Run last = runs.get(runs.size() - 1);
        if (!s.expectProvider.isEmpty()) {
            for (Run r : runs) if (!r.prov.equals(s.expectProvider)) return null;
        }
        if (!statuses.isEmpty()) {
            for (Run r : runs) if (!statuses.contains(r.status)) return null;
        }
        if (!colos.isEmpty()) {
            for (Run r : runs) if (!colos.contains(r.colo.toUpperCase(Locale.ROOT))) return null;
        }
        double[] tot = new double[runs.size()];
        double sumTot = 0, sumTcp = 0, sumTls = 0, sumTtfb = 0;
        for (int i = 0; i < runs.size(); i++) {
            Run r = runs.get(i);
            tot[i] = r.tcp + r.tls + r.ttfb;
            sumTot += tot[i];
            sumTcp += r.tcp;
            sumTls += r.tls;
            sumTtfb += r.ttfb;
        }
        int n = runs.size();
        double meanTot = sumTot / n;
        double jit = 0;
        if (n > 1) {
            double var = 0;
            for (double t : tot) var += (t - meanTot) * (t - meanTot);
            jit = Math.sqrt(var / n);
        }
        if ((s.maxTotal > 0 && meanTot > s.maxTotal) || (s.maxJitter > 0 && jit > s.maxJitter)) return null;
        int loss = (int) Math.round(100.0 * (1.0 - (double) n / s.tries));
        Result res = new Result();
        res.ip = ip;
        res.port = port;
        res.ok = n;
        res.tries = s.tries;
        res.loss = loss;
        res.ping = (int) Math.round(sumTcp / n);
        res.tls = (int) Math.round(sumTls / n);
        res.ttfb = (int) Math.round(sumTtfb / n);
        res.total = (int) Math.round(meanTot);
        res.jitter = (int) Math.round(jit);
        res.status = last.status;
        res.provider = last.prov;
        res.colo = last.colo;
        res.server = last.server;
        res.score = (int) Math.round(meanTot + jit * 1.5 + loss * 10);
        return res;
    }

    private double speedTest(String ip, int port, Settings s, SSLSocketFactory f) {
        int timeoutMs = (int) (s.timeout * 1000);
        Socket raw = new Socket();
        SSLSocket tls = null;
        try {
            raw.connect(new InetSocketAddress(ip, port), timeoutMs);
            tls = wrapTls(raw, f, s, port);
            tls.setSoTimeout(timeoutMs);
            tls.startHandshake();
            String req = "GET " + s.speedPath + " HTTP/1.1\r\nHost: " + s.host
                    + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
            tls.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
            tls.getOutputStream().flush();
            InputStream in = tls.getInputStream();
            byte[] buf = new byte[65536];
            ByteArrayOutputStream hdr = new ByteArrayOutputStream();
            boolean hdrDone = false;
            long got = 0;
            long t0 = System.nanoTime();
            while ((System.nanoTime() - t0) / 1e9 < 6) {
                int n = in.read(buf);
                if (n <= 0) break;
                if (!hdrDone) {
                    hdr.write(buf, 0, n);
                    String sofar = new String(hdr.toByteArray(), StandardCharsets.ISO_8859_1);
                    int c = sofar.indexOf("\r\n\r\n");
                    if (c >= 0) {
                        hdrDone = true;
                        got = sofar.length() - (c + 4);
                        t0 = System.nanoTime();
                    }
                } else {
                    got += n;
                }
            }
            double el = (System.nanoTime() - t0) / 1e9;
            return (el > 0.2 && got > 0) ? Math.round(got * 8 / 1e6 / el * 10) / 10.0 : 0.0;
        } catch (Exception e) {
            return 0.0;
        } finally {
            try { if (tls != null) tls.close(); } catch (IOException ignored) {}
            try { raw.close(); } catch (IOException ignored) {}
        }
    }

    // ───────── run ─────────

    public void start(Input in, Settings s) {
        stopFlag.set(false);
        new Thread(() -> {
            try {
                run(in, s);
            } catch (Exception e) {
                listener.onError(e.getMessage() != null ? e.getMessage() : "scan failed");
            }
        }, "darknet-scanner").start();
    }

    private static int clampI(int v, int lo, int hi) {
        return Math.max(lo, Math.min(hi, v));
    }

    private void run(Input in, Settings s) throws Exception {
        s.tries = clampI(s.tries, 1, 10);
        s.minOk = clampI(s.minOk, 1, s.tries);
        s.threads = clampI(s.threads, 1, 300);
        s.maxIps = clampI(s.maxIps, 1, 50000);
        s.timeout = Math.max(0.5, Math.min(15, s.timeout));
        s.speedTop = clampI(s.speedTop, 1, 20);
        if (s.sni == null || s.sni.trim().isEmpty()) s.sni = "speed.cloudflare.com";
        s.sni = s.sni.trim();
        s.host = (s.host == null || s.host.trim().isEmpty()) ? s.sni : s.host.trim();
        s.path = (s.path == null || s.path.trim().isEmpty()) ? "/cdn-cgi/trace" : s.path.trim();
        s.speedPath = (s.speedPath == null || s.speedPath.trim().isEmpty()) ? "/__down?bytes=3000000" : s.speedPath.trim();
        s.expectProvider = s.expectProvider == null ? "" : s.expectProvider.trim().toLowerCase(Locale.ROOT);
        if (!"4".equals(s.ipver) && !"6".equals(s.ipver) && !"both".equals(s.ipver)) s.ipver = "4";

        String text;
        if ("range".equals(in.mode)) {
            text = in.startIp.trim() + "-" + in.endIp.trim();
        } else if ("preset".equals(in.mode)) {
            StringBuilder sb = new StringBuilder();
            if (!"custom".equals(in.provider)) {
                for (String r : providerRanges(in.provider)) sb.append(r).append('\n');
            }
            text = sb.append(in.customRanges == null ? "" : in.customRanges).toString();
            if ((in.provider.equals("cloudflare") || in.provider.equals("fastly")) && s.expectProvider.isEmpty()) {
                s.expectProvider = in.provider;
            }
        } else {
            text = expandDomains(in.listText, s.ipver);
        }
        if (stopFlag.get()) { listener.onFinished(new ArrayList<Result>(), true); return; }

        Random rnd = new Random();
        BigInteger[] space = new BigInteger[]{BigInteger.ZERO};
        List<String> ips = pick(subtract(parseTargets(text), parseTargets(s.exclude)), s.maxIps, s.ipver, rnd, space);
        if (ips.isEmpty()) {
            listener.onError("No valid public IPs for the selected IP version");
            return;
        }
        List<Integer> ports = new ArrayList<>();
        Matcher pm = Pattern.compile("\\d{1,5}").matcher(s.ports == null ? "" : s.ports);
        while (pm.find() && ports.size() < 8) {
            int p = Integer.parseInt(pm.group());
            if (p >= 1 && p <= 65535 && !ports.contains(p)) ports.add(p);
        }
        if (ports.isEmpty()) ports.add(443);

        Set<Integer> statuses = new HashSet<>();
        Matcher sm = Pattern.compile("\\d{3}").matcher(s.statuses == null ? "" : s.statuses);
        while (sm.find()) statuses.add(Integer.parseInt(sm.group()));
        Set<String> colos = new HashSet<>();
        Matcher cm = Pattern.compile("[A-Za-z]{2,5}").matcher(s.colos == null ? "" : s.colos);
        while (cm.find()) colos.add(cm.group().toUpperCase(Locale.ROOT));

        final SSLSocketFactory f = factory(s.verify);
        final int total = ips.size() * ports.size();
        listener.onInit(total, space[0].toString());

        final List<Result> results = Collections.synchronizedList(new ArrayList<Result>());
        final AtomicInteger done = new AtomicInteger(0);
        ExecutorService ex = Executors.newFixedThreadPool(s.threads);
        pool = ex;
        for (String ip : ips) {
            for (int port : ports) {
                final String fip = ip;
                final int fport = port;
                try {
                    ex.submit(() -> {
                        if (stopFlag.get()) return;
                        Result r = testIp(fip, fport, s, f, statuses, colos);
                        if (stopFlag.get()) return;
                        int d = done.incrementAndGet();
                        listener.onProgress(d, total, fip, r != null ? r.ping : -1);
                        if (r != null) {
                            results.add(r);
                            listener.onResult(r);
                        }
                    });
                } catch (Exception rejected) {
                    break;
                }
            }
            if (stopFlag.get()) break;
        }
        ex.shutdown();
        try {
            ex.awaitTermination(60, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {
        }

        List<Result> list = new ArrayList<>(results);
        if (s.speed && !list.isEmpty() && !stopFlag.get()) {
            Collections.sort(list, (a, b) -> Integer.compare(a.score, b.score));
            List<Result> top = new ArrayList<>(list.subList(0, Math.min(s.speedTop, list.size())));
            listener.onPhase("Speed test: " + top.size() + " best IPs…");
            ExecutorService sx = Executors.newFixedThreadPool(3);
            pool = sx;
            List<java.util.concurrent.Future<?>> futs = new ArrayList<>();
            for (Result r : top) {
                futs.add(sx.submit(() -> {
                    if (stopFlag.get()) return;
                    r.mbps = speedTest(r.ip, r.port, s, f);
                    listener.onSpeed(r.ip, r.port, r.mbps);
                }));
            }
            sx.shutdown();
            for (java.util.concurrent.Future<?> fu : futs) {
                try { fu.get(); } catch (Exception ignored) { }
            }
        }
        if ("ping".equals(s.sortBy)) {
            Collections.sort(list, (a, b) -> Integer.compare(a.ping, b.ping));
        } else if ("speed".equals(s.sortBy)) {
            Collections.sort(list, (a, b) -> Double.compare(Math.max(b.mbps, 0), Math.max(a.mbps, 0)));
        } else {
            Collections.sort(list, (a, b) -> Integer.compare(a.score, b.score));
        }
        listener.onFinished(list, stopFlag.get());
    }
}
