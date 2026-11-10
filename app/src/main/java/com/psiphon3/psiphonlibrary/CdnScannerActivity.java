package com.psiphon3.psiphonlibrary;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.psiphon3.R;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DARKNET CDN IP scanner screen. Mirrors the "CDN IP Scanner v3" tool:
 * preset CDNs / IP list / range, multi-try probing, scoring and optional speed test.
 */
public class CdnScannerActivity extends AppCompatActivity implements CdnScannerEngine.Listener {

    private static final int MAX_SHOWN = 300;

    private static final String[] MODES = {"Preset CDN", "IP list / domains", "IP range"};
    private static final String[] MODE_KEYS = {"preset", "list", "range"};
    private static final String[] PROVIDERS = {"Cloudflare", "Fastly", "Akamai", "Custom CDN"};
    private static final String[] PROVIDER_KEYS = {"cloudflare", "fastly", "akamai", "custom"};
    private static final String[] IPVERS = {"IPv4 only", "IPv6 only", "IPv4 + IPv6"};
    private static final String[] IPVER_KEYS = {"4", "6", "both"};
    private static final String[] METHODS = {"GET", "HEAD"};
    private static final String[] EXPECTS = {"Any CDN", "Cloudflare only", "Fastly only", "Akamai only"};
    private static final String[] EXPECT_KEYS = {"", "cloudflare", "fastly", "akamai"};
    private static final String[] SORTS = {"Best score (ping+jitter+loss)", "Lowest ping", "Highest speed"};
    private static final String[] SORT_KEYS = {"score", "ping", "speed"};

    private TextView statusText;
    private TextView currentIpText;
    private TextView pingText;
    private TextView progressText;
    private ProgressBar progressBar;
    private Button startBtn;
    private Button stopBtn;
    private Button applyBtn;
    private Button copyBtn;
    private Button toggleAdvBtn;
    private Spinner modeSpinner;
    private Spinner providerSpinner;
    private EditText customRangesInput;
    private EditText listTextInput;
    private EditText startIpInput;
    private EditText endIpInput;
    private View rangeBox;
    private LinearLayout advBox;
    private RecyclerView resultsList;

    // advanced settings widgets
    private Spinner ipverSpin;
    private Spinner methodSpin;
    private Spinner expectSpin;
    private Spinner sortSpin;
    private EditText fTries;
    private EditText fMinOk;
    private EditText fThreads;
    private EditText fTimeout;
    private EditText fPorts;
    private EditText fMaxIps;
    private EditText fSni;
    private EditText fHost;
    private EditText fPath;
    private EditText fStatuses;
    private EditText fSpeedTop;
    private EditText fSpeedPath;
    private EditText fMaxTotal;
    private EditText fMaxJitter;
    private EditText fColos;
    private EditText fExclude;
    private CheckBox verifyCheck;
    private CheckBox speedCheck;

    private CdnScannerEngine engine;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean running = new AtomicBoolean(false);

    private final List<CdnScannerEngine.Result> results = new ArrayList<>();
    private ResultsAdapter adapter;
    private String sortKey = "score";

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cdn_scanner);

        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle("DARKNET Scanner");
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        statusText = findViewById(R.id.scanner_status);
        currentIpText = findViewById(R.id.scanner_current_ip);
        pingText = findViewById(R.id.scanner_ping);
        progressText = findViewById(R.id.scanner_progress_text);
        progressBar = findViewById(R.id.scanner_progress);
        startBtn = findViewById(R.id.scanner_start);
        stopBtn = findViewById(R.id.scanner_stop);
        applyBtn = findViewById(R.id.scanner_apply);
        copyBtn = findViewById(R.id.scanner_copy);
        toggleAdvBtn = findViewById(R.id.scanner_toggle_adv);
        modeSpinner = findViewById(R.id.scanner_mode);
        providerSpinner = findViewById(R.id.scanner_provider);
        customRangesInput = findViewById(R.id.scanner_custom_ranges);
        listTextInput = findViewById(R.id.scanner_list_text);
        startIpInput = findViewById(R.id.scanner_start_ip);
        endIpInput = findViewById(R.id.scanner_end_ip);
        rangeBox = findViewById(R.id.scanner_range_box);
        advBox = findViewById(R.id.scanner_adv_box);
        resultsList = findViewById(R.id.scanner_results);

        modeSpinner.setAdapter(spinnerAdapter(MODES));
        providerSpinner.setAdapter(spinnerAdapter(PROVIDERS));
        buildAdvancedSettings();

        modeSpinner.setOnItemSelectedListener(new SimpleSelect() {
            @Override
            void onSelected(int position) {
                boolean preset = position == 0;
                providerSpinner.setVisibility(preset ? View.VISIBLE : View.GONE);
                customRangesInput.setVisibility(preset ? View.VISIBLE : View.GONE);
                listTextInput.setVisibility(position == 1 ? View.VISIBLE : View.GONE);
                rangeBox.setVisibility(position == 2 ? View.VISIBLE : View.GONE);
            }
        });
        providerSpinner.setOnItemSelectedListener(new SimpleSelect() {
            @Override
            void onSelected(int position) {
                applyProviderPreset(PROVIDER_KEYS[position]);
            }
        });
        toggleAdvBtn.setOnClickListener(v -> {
            boolean show = advBox.getVisibility() != View.VISIBLE;
            advBox.setVisibility(show ? View.VISIBLE : View.GONE);
            toggleAdvBtn.setText(show ? "Advanced settings ▴" : "Advanced settings ▾");
        });

        adapter = new ResultsAdapter(results);
        resultsList.setLayoutManager(new LinearLayoutManager(this));
        resultsList.setAdapter(adapter);

        engine = new CdnScannerEngine(this);

        startBtn.setOnClickListener(v -> startScan());
        stopBtn.setOnClickListener(v -> stopScan());
        applyBtn.setOnClickListener(v -> applyBestToCdnFronting(false));
        copyBtn.setOnClickListener(v -> copyBestIps());

        resetUiIdle();
    }

    // ───────── UI helpers ─────────

    private ArrayAdapter<String> spinnerAdapter(String[] items) {
        return new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, items);
    }

    private abstract static class SimpleSelect implements AdapterView.OnItemSelectedListener {
        abstract void onSelected(int position);

        @Override
        public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
            onSelected(position);
        }

        @Override
        public void onNothingSelected(AdapterView<?> parent) {
        }
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void addLabel(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(0xFF8B949E);
        t.setTextSize(12f);
        t.setPadding(0, dp(8), 0, dp(2));
        advBox.addView(t);
    }

    private EditText addField(String label, String value, boolean numeric, boolean multiline) {
        addLabel(label);
        EditText e = new EditText(this);
        e.setText(value);
        e.setTextColor(0xFFE6EDF3);
        e.setHintTextColor(0xFF8B949E);
        e.setTextSize(13f);
        e.setBackgroundColor(0xFF21262D);
        e.setPadding(dp(8), dp(8), dp(8), dp(8));
        if (multiline) {
            e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            e.setMinLines(2);
            e.setGravity(android.view.Gravity.TOP | android.view.Gravity.START);
        } else if (numeric) {
            e.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_DECIMAL);
        } else {
            e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            e.setSingleLine(true);
        }
        advBox.addView(e, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return e;
    }

    private Spinner addSpinner(String label, String[] items) {
        addLabel(label);
        Spinner s = new Spinner(this);
        s.setAdapter(spinnerAdapter(items));
        s.setBackgroundColor(0xFF21262D);
        s.setPadding(dp(8), dp(8), dp(8), dp(8));
        advBox.addView(s, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return s;
    }

    private CheckBox addCheck(String label, boolean checked) {
        CheckBox c = new CheckBox(this);
        c.setText(label);
        c.setTextColor(0xFFE6EDF3);
        c.setChecked(checked);
        advBox.addView(c, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return c;
    }

    private void buildAdvancedSettings() {
        CdnScannerEngine.Settings d = new CdnScannerEngine.Settings();
        ipverSpin = addSpinner("IP version", IPVERS);
        fTries = addField("Tries per IP", String.valueOf(d.tries), true, false);
        fMinOk = addField("Min successful tries", String.valueOf(d.minOk), true, false);
        fThreads = addField("Threads", String.valueOf(d.threads), true, false);
        fTimeout = addField("Timeout (seconds)", String.valueOf(d.timeout), true, false);
        fPorts = addField("Ports (comma separated)", d.ports, false, false);
        fMaxIps = addField("Max IPs to test", String.valueOf(d.maxIps), true, false);
        fSni = addField("SNI (TLS domain)", d.sni, false, false);
        fHost = addField("Host (HTTP header)", d.host, false, false);
        fPath = addField("Request path", d.path, false, false);
        methodSpin = addSpinner("Method", METHODS);
        expectSpin = addSpinner("Accept only this CDN", EXPECTS);
        fStatuses = addField("Allowed status codes (empty = any)", d.statuses, false, false);
        sortSpin = addSpinner("Sort results by", SORTS);
        verifyCheck = addCheck("Verify TLS certificate", true);
        speedCheck = addCheck("Download speed test for the best IPs", false);
        fSpeedTop = addField("How many best IPs to speed-test", String.valueOf(d.speedTop), true, false);
        fSpeedPath = addField("Speed test path", d.speedPath, false, false);
        fMaxTotal = addField("Max total time (ms, 0 = no limit)", "0", true, false);
        fMaxJitter = addField("Max jitter (ms, 0 = no limit)", "0", true, false);
        fColos = addField("Only these colos (e.g. FRA, AMS, DXB)", "", false, false);
        fExclude = addField("Exclude IPs / ranges", "", false, true);
    }

    private void applyProviderPreset(String key) {
        CdnScannerEngine.Settings p = new CdnScannerEngine.Settings();
        p.applyPreset(key);
        if ("custom".equals(key)) {
            expectSpin.setSelection(0);
            return;
        }
        fSni.setText(p.sni);
        fHost.setText(p.host);
        fPath.setText(p.path);
        fSpeedPath.setText(p.speedPath);
        fStatuses.setText(p.statuses);
        expectSpin.setSelection(0);
    }

    private static int toInt(EditText e, int def) {
        try {
            return Integer.parseInt(e.getText().toString().trim());
        } catch (Exception ex) {
            return def;
        }
    }

    private static double toDouble(EditText e, double def) {
        try {
            return Double.parseDouble(e.getText().toString().trim());
        } catch (Exception ex) {
            return def;
        }
    }

    private static String txt(EditText e) {
        return e.getText().toString().trim();
    }

    private CdnScannerEngine.Settings collectSettings() {
        CdnScannerEngine.Settings s = new CdnScannerEngine.Settings();
        s.ipver = IPVER_KEYS[ipverSpin.getSelectedItemPosition()];
        s.tries = toInt(fTries, 3);
        s.minOk = toInt(fMinOk, 2);
        s.threads = toInt(fThreads, 100);
        s.timeout = toDouble(fTimeout, 3.0);
        s.ports = txt(fPorts);
        s.maxIps = toInt(fMaxIps, 1000);
        s.sni = txt(fSni);
        s.host = txt(fHost);
        s.path = txt(fPath);
        s.head = methodSpin.getSelectedItemPosition() == 1;
        s.expectProvider = EXPECT_KEYS[expectSpin.getSelectedItemPosition()];
        s.statuses = txt(fStatuses);
        s.sortBy = SORT_KEYS[sortSpin.getSelectedItemPosition()];
        s.verify = verifyCheck.isChecked();
        s.speed = speedCheck.isChecked();
        s.speedTop = toInt(fSpeedTop, 5);
        s.speedPath = txt(fSpeedPath);
        s.maxTotal = toInt(fMaxTotal, 0);
        s.maxJitter = toInt(fMaxJitter, 0);
        s.colos = txt(fColos);
        s.exclude = fExclude.getText().toString();
        return s;
    }

    // ───────── lifecycle ─────────

    @Override
    public boolean onSupportNavigateUp() {
        finish();
        return true;
    }

    @Override
    protected void onDestroy() {
        stopScan();
        super.onDestroy();
    }

    private void startScan() {
        if (running.get()) return;

        CdnScannerEngine.Input in = new CdnScannerEngine.Input();
        in.mode = MODE_KEYS[modeSpinner.getSelectedItemPosition()];
        in.provider = PROVIDER_KEYS[providerSpinner.getSelectedItemPosition()];
        in.customRanges = customRangesInput.getText().toString();
        in.listText = listTextInput.getText().toString();
        in.startIp = txt(startIpInput);
        in.endIp = txt(endIpInput);

        if ("list".equals(in.mode) && in.listText.trim().isEmpty()) {
            Toast.makeText(this, "Enter at least one IP, range or domain", Toast.LENGTH_SHORT).show();
            return;
        }
        if ("range".equals(in.mode) && (in.startIp.isEmpty() || in.endIp.isEmpty())) {
            Toast.makeText(this, "Enter start and end IP", Toast.LENGTH_SHORT).show();
            return;
        }
        if ("preset".equals(in.mode) && "custom".equals(in.provider) && in.customRanges.trim().isEmpty()) {
            Toast.makeText(this, "Enter at least one IP or CIDR", Toast.LENGTH_SHORT).show();
            return;
        }

        CdnScannerEngine.Settings s = collectSettings();
        sortKey = s.sortBy;

        running.set(true);
        results.clear();
        adapter.notifyDataSetChanged();

        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        applyBtn.setEnabled(false);
        copyBtn.setEnabled(false);
        progressBar.setIndeterminate(false);
        progressBar.setProgress(0);
        statusText.setText("Scanning…");
        currentIpText.setText("—");
        pingText.setText("—");
        progressText.setText("0 / 0");

        engine.start(in, s);
    }

    private void stopScan() {
        running.set(false);
        if (engine != null) {
            engine.stop();
        }
        mainHandler.post(() -> {
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            statusText.setText(results.isEmpty() ? "Stopped" : "Stopped — " + results.size() + " good IPs");
            applyBtn.setEnabled(!results.isEmpty());
            copyBtn.setEnabled(!results.isEmpty());
        });
    }

    private void resetUiIdle() {
        statusText.setText("Ready");
        currentIpText.setText("—");
        pingText.setText("—");
        progressText.setText("0 / 0");
        progressBar.setProgress(0);
        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        applyBtn.setEnabled(false);
        copyBtn.setEnabled(false);
    }

    private Comparator<CdnScannerEngine.Result> comparator() {
        if ("ping".equals(sortKey)) {
            return (a, b) -> Integer.compare(a.ping, b.ping);
        } else if ("speed".equals(sortKey)) {
            return (a, b) -> Double.compare(Math.max(b.mbps, 0), Math.max(a.mbps, 0));
        }
        return (a, b) -> Integer.compare(a.score, b.score);
    }

    // ───────── engine callbacks (background thread → post to main) ─────────

    @Override
    public void onInit(int total, String space) {
        mainHandler.post(() -> {
            progressBar.setMax(Math.max(total, 1));
            progressText.setText("0 / " + total);
            statusText.setText("Scanning " + total + " targets…");
        });
    }

    @Override
    public void onProgress(int done, int total, String currentIp, int lastPingMs) {
        mainHandler.post(() -> {
            progressBar.setMax(Math.max(total, 1));
            progressBar.setProgress(done);
            progressText.setText(done + " / " + total);
            currentIpText.setText(currentIp != null ? currentIp : "—");
            pingText.setText(lastPingMs >= 0 ? lastPingMs + " ms" : "timeout");
        });
    }

    @Override
    public void onResult(CdnScannerEngine.Result result) {
        mainHandler.post(() -> {
            results.add(result);
            Collections.sort(results, comparator());
            while (results.size() > MAX_SHOWN) {
                results.remove(results.size() - 1);
            }
            adapter.notifyDataSetChanged();
            applyBtn.setEnabled(true);
            copyBtn.setEnabled(true);
            statusText.setText("Scanning… " + results.size() + " good IPs");
        });
    }

    @Override
    public void onPhase(String text) {
        mainHandler.post(() -> statusText.setText(text));
    }

    @Override
    public void onSpeed(String ip, int port, double mbps) {
        mainHandler.post(() -> adapter.notifyDataSetChanged());
    }

    @Override
    public void onFinished(List<CdnScannerEngine.Result> sorted, boolean stopped) {
        mainHandler.post(() -> {
            running.set(false);
            results.clear();
            results.addAll(sorted.size() > MAX_SHOWN ? sorted.subList(0, MAX_SHOWN) : sorted);
            adapter.notifyDataSetChanged();
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            statusText.setText((stopped ? "Stopped — " : "Done — ") + sorted.size() + " good IPs");
            applyBtn.setEnabled(!results.isEmpty());
            copyBtn.setEnabled(!results.isEmpty());
            // Scan ended (finished or stopped): put the best IPs into the CDN edge IPs list
            applyBestToCdnFronting(true);
        });
    }

    @Override
    public void onError(String message) {
        mainHandler.post(() -> {
            statusText.setText("Error: " + message);
            running.set(false);
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
        });
    }

    // ───────── actions ─────────

    private void applyBestToCdnFronting(boolean auto) {
        StringBuilder sb = new StringBuilder();
        int take = 0;
        for (CdnScannerEngine.Result r : results) {
            if (r.ip.indexOf(':') >= 0) continue; // IPv4 only for CDN Fronting
            if (take >= 12) break;
            if (take > 0) sb.append(',');
            sb.append(r.ip);
            take++;
        }
        if (take == 0) {
            if (!auto) {
                Toast.makeText(this, "No IPv4 results to apply", Toast.LENGTH_SHORT).show();
            }
            return; // never wipe the existing list when nothing good was found
        }
        // Same preference file + key as the "CDN edge IPs" setting in More Options
        getSharedPreferences(getString(R.string.moreOptionsPreferencesName), Context.MODE_PRIVATE)
                .edit()
                .putString(getString(R.string.cdnFrontingCustomIpListPreference), sb.toString())
                .apply();

        Toast.makeText(this, (auto ? "Saved top " : "Applied top ") + take
                + " IPs to CDN edge IPs. Reconnect to use them.", Toast.LENGTH_LONG).show();
    }

    private void copyBestIps() {
        if (results.isEmpty()) return;
        int take = Math.min(20, results.size());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < take; i++) {
            if (i > 0) sb.append('\n');
            sb.append(results.get(i).ip);
        }
        ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("darknet_cdn_ips", sb.toString()));
        Toast.makeText(this, "Copied " + take + " IPs", Toast.LENGTH_SHORT).show();
    }

    // ───────── results list ─────────

    private static class ResultsAdapter extends RecyclerView.Adapter<ResultsAdapter.VH> {
        private final List<CdnScannerEngine.Result> data;

        ResultsAdapter(List<CdnScannerEngine.Result> data) {
            this.data = data;
        }

        static class VH extends RecyclerView.ViewHolder {
            TextView line;

            VH(View v) {
                super(v);
                line = (TextView) v;
            }
        }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            TextView tv = new TextView(parent.getContext());
            tv.setTextColor(0xFFE0E0E0);
            tv.setTextSize(12.5f);
            tv.setPadding(24, 14, 24, 14);
            tv.setLayoutParams(new RecyclerView.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
            return new VH(tv);
        }

        @Override
        public void onBindViewHolder(VH holder, int position) {
            CdnScannerEngine.Result r = data.get(position);
            String ipPort = r.port != 443 ? r.ip + ":" + r.port : r.ip;
            StringBuilder sb = new StringBuilder();
            sb.append(String.format(Locale.US, "#%d  %s\n", position + 1, ipPort));
            sb.append(String.format(Locale.US,
                    "total %dms  (tcp %d · tls %d · ttfb %d)  jitter %d  loss %d%%",
                    r.total, r.ping, r.tls, r.ttfb, r.jitter, r.loss));
            sb.append("\n").append(r.provider);
            if (r.colo != null && !r.colo.isEmpty()) sb.append(" · ").append(r.colo);
            sb.append(" · HTTP ").append(r.status);
            if (r.mbps >= 0) sb.append(String.format(Locale.US, " · %.1f Mbps", r.mbps));
            holder.line.setText(sb.toString());
        }

        @Override
        public int getItemCount() {
            return data.size();
        }
    }
}
