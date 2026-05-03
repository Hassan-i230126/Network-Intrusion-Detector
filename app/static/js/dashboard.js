/**
 * dashboard.js — Main application logic for the NIDS dashboard.
 *
 * Fetches metrics data, initializes Chart.js instances, sets up
 * navigation, populates static data, and starts SSE streaming.
 */

/* global Chart, initClassDistributionChart, initModelComparisonChart, initROCChart,
   initFeatureImportanceChart, initTimelineChart, initSessionDonutChart,
   initConfidenceHistogram, initLiveTimelineChart, initAttackSubtypeChart,
   buildConfusionMatrices, initSSE, animateCounter */

// ── Global Application State ──
const AppState = {
    activeModel: 'rf',
    captureStatus: 'stopped',
    sessionCounts: { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 },
    totalFlows: 0,
    recentFlows: [],
    charts: {},
    metrics: null,
    sseClient: null
};

// ── Navigation ──
function setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page-section');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetPage = link.dataset.page;

            // Update active states
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Page transition
            pages.forEach(p => {
                if (p.id === `page-${targetPage}`) {
                    p.classList.add('active');
                    // Resize charts on page switch
                    setTimeout(() => {
                        Object.values(AppState.charts).forEach(chart => {
                            if (chart && typeof chart.resize === 'function') {
                                chart.resize();
                            }
                        });
                    }, 250);
                } else {
                    p.classList.remove('active');
                }
            });
        });
    });
}

// ── Model Selector ──
function setupModelSelector() {
    const selector = document.getElementById('model-selector');
    if (!selector) return;

    selector.addEventListener('change', async (e) => {
        const model = e.target.value;
        AppState.activeModel = model;

        try {
            await fetch('/api/capture/model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ model })
            });
        } catch (err) {
            console.error('Failed to switch model:', err);
        }

        updateStatCards();
    });
}

// ── Capture Controls ──
function setupCaptureControls() {
    const startBtn = document.getElementById('btn-capture-start');
    const stopBtn = document.getElementById('btn-capture-stop');

    if (startBtn) {
        startBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/capture/start');
                const data = await res.json();
                AppState.captureStatus = data.status;
                updateCaptureStatusUI();
            } catch (e) { console.error(e); }
        });
    }

    if (stopBtn) {
        stopBtn.addEventListener('click', async () => {
            try {
                const res = await fetch('/api/capture/stop');
                const data = await res.json();
                AppState.captureStatus = 'stopped';
                updateCaptureStatusUI();
            } catch (e) { console.error(e); }
        });
    }
}

function updateCaptureStatusUI() {
    const dot = document.getElementById('capture-dot');
    const text = document.getElementById('capture-text');
    const modeEl = document.getElementById('live-capture-mode');

    if (dot) {
        dot.className = `status-dot ${AppState.captureStatus}`;
    }
    if (text) {
        const labels = { running: 'Live Capture', simulating: 'Simulating', stopped: 'Stopped' };
        text.textContent = labels[AppState.captureStatus] || AppState.captureStatus;
    }
    if (modeEl) {
        modeEl.textContent = AppState.captureStatus === 'simulating' ? 'SIMULATION' : 'LIVE';
    }
}

// ── Populate Metrics Table ──
function populateMetricsTable(metricsData) {
    const tbody = document.getElementById('metrics-table-body');
    if (!tbody || !metricsData) return;

    const models = metricsData.models;
    const modelDisplay = {
        decision_tree: 'Decision Tree',
        random_forest: 'Random Forest',
        xgboost: 'XGBoost',
        stacked: 'Stacked Ensemble'
    };

    // Find best values
    const keys = ['accuracy', 'f1_weighted', 'precision_weighted', 'recall_weighted', 'roc_auc'];
    const best = {};
    keys.forEach(k => {
        best[k] = Math.max(...Object.values(models).map(m => m[k] || 0));
    });
    best.fpr = Math.min(...Object.values(models).map(m => m.fpr || 1));

    tbody.innerHTML = '';

    for (const [modelKey, displayName] of Object.entries(modelDisplay)) {
        if (!models[modelKey]) continue;
        const m = models[modelKey];
        const tr = document.createElement('tr');

        function td(val, key, lowerBetter = false) {
            const isBest = lowerBetter ? val === best[key] : val === best[key];
            return `<td class="${isBest ? 'best-value' : ''}">${val.toFixed(4)}</td>`;
        }

        tr.innerHTML = `
            <td style="font-weight:600">${displayName}</td>
            ${td(m.accuracy || 0, 'accuracy')}
            ${td(m.f1_weighted || 0, 'f1_weighted')}
            ${td(m.precision_weighted || 0, 'precision_weighted')}
            ${td(m.recall_weighted || 0, 'recall_weighted')}
            ${td(m.fpr || 0, 'fpr', true)}
            ${td(m.roc_auc || 0, 'roc_auc')}
            <td>${(m.train_time_seconds || 0).toFixed(1)}s</td>
            <td>${(m.inference_time_ms_per_1000 || 0).toFixed(2)}ms</td>
        `;
        tbody.appendChild(tr);
    }
}

// ── Populate Dataset Stats ──
function populateDatasetStats(stats) {
    const el = (id) => document.getElementById(id);

    if (el('ds-total-records')) el('ds-total-records').textContent = ((stats.train_size || 0) + (stats.test_size || 0)).toLocaleString();
    if (el('ds-train-size')) el('ds-train-size').textContent = (stats.train_size || 0).toLocaleString();
    if (el('ds-test-size')) el('ds-test-size').textContent = (stats.test_size || 0).toLocaleString();
    if (el('ds-feature-count')) el('ds-feature-count').textContent = stats.n_features_after_preprocessing || stats.n_original_features || 41;
}

// ── Populate Feature Analysis Summary ──
function populateFeatureSummary(featureImportance) {
    const container = document.getElementById('feature-summary-text');
    if (!container || !featureImportance) return;

    // Get top 5 features from RF
    const rfFeatures = featureImportance.random_forest || [];
    const top5 = rfFeatures.slice(0, 5);

    if (top5.length === 0) {
        container.innerHTML = '<p>Feature importance data will be available after running the pipeline.</p>';
        return;
    }

    const featureDescriptions = {
        'src_bytes': 'the number of bytes sent from source to destination — high values can indicate data exfiltration or DoS payload delivery',
        'dst_bytes': 'the number of bytes from destination to source — asymmetric traffic patterns often indicate reconnaissance or denial-of-service',
        'service': 'the network service on the destination port — certain services (telnet, ftp) are inherently more vulnerable to attacks',
        'flag': 'the TCP connection status flag — abnormal flags like S0 (no SYN-ACK) strongly indicate SYN flood attacks',
        'count': 'connections to the same host in a time window — high counts suggest brute-force or flooding attacks',
        'srv_count': 'connections to the same service — repeated service access patterns reveal automated scanning',
        'logged_in': 'whether the user successfully authenticated — distinguishes legitimate access from failed intrusion attempts',
        'serror_rate': 'the rate of SYN errors — elevated rates are a hallmark of SYN flood DoS attacks',
        'same_srv_rate': 'fraction of connections to the same service — low diversity indicates targeted attacks',
        'dst_host_srv_count': 'connections to the same service on the destination host — high values indicate service-specific attacks',
        'dst_host_same_srv_rate': 'proportion of connections to the same service on the destination — helps identify focused service exploitation',
        'dst_host_serror_rate': 'SYN error rate for the destination host — elevated values indicate the host is under SYN flood attack',
        'dst_host_srv_serror_rate': 'SYN error rate per service — pinpoints which specific service is being targeted',
        'dst_host_rerror_rate': 'rejection error rate for the destination — high rates indicate port scanning or connection rejection patterns',
        'diff_srv_rate': 'fraction of connections to different services — high values indicate port scanning activity',
        'duration': 'the length of the connection in seconds — very short or very long connections can indicate anomalies',
        'hot': 'number of "hot" indicators in the content — higher values suggest suspicious content access',
        'wrong_fragment': 'count of wrong fragments — used in fragmentation-based attacks like teardrop',
        'src_dst_byte_ratio': 'the ratio of source to destination bytes — extreme ratios indicate one-directional data flows typical of attacks',
        'protocol_type': 'the transport protocol used (TCP/UDP/ICMP) — different attack types favor different protocols',
    };

    let html = '<h4>Feature Importance Analysis</h4>';
    html += '<p>The following features were identified as the most discriminative for classifying network traffic:</p>';

    top5.forEach((feat, i) => {
        const name = feat.feature;
        const desc = featureDescriptions[name] || 'contributes significantly to the model\'s classification decisions';
        html += `<p><span class="feature-highlight">${i + 1}. ${name}</span> (importance: ${feat.importance.toFixed(4)}) — ${desc}.</p>`;
    });

    html += '<p>These features collectively capture the most critical behavioral patterns that distinguish normal network traffic from various attack types in the NSL-KDD dataset.</p>';

    container.innerHTML = html;
}

// ── Set Best Model F1 ──
function setBestModelF1(metricsData) {
    const el = document.getElementById('stat-best-f1');
    const badge = document.getElementById('stat-best-model-name');
    if (!el || !metricsData || !metricsData.models) return;

    let bestF1 = 0;
    let bestModel = '';
    const modelDisplay = {
        decision_tree: 'DT',
        random_forest: 'RF',
        xgboost: 'XGB',
        stacked: 'Stack'
    };

    for (const [name, metrics] of Object.entries(metricsData.models)) {
        if ((metrics.f1_weighted || 0) > bestF1) {
            bestF1 = metrics.f1_weighted;
            bestModel = name;
        }
    }

    el.textContent = bestF1.toFixed(4);
    if (badge) badge.textContent = modelDisplay[bestModel] || bestModel;
}

// ── Table Sorting ──
function setupTableSorting() {
    document.querySelectorAll('.data-table thead th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const colIdx = Array.from(th.parentNode.children).indexOf(th);
            const rows = Array.from(tbody.querySelectorAll('tr'));

            const isAsc = th.dataset.sortDir !== 'asc';
            th.dataset.sortDir = isAsc ? 'asc' : 'desc';

            rows.sort((a, b) => {
                let aVal = a.children[colIdx]?.textContent.trim() || '';
                let bVal = b.children[colIdx]?.textContent.trim() || '';

                const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));

                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? aNum - bNum : bNum - aNum;
                }
                return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });

            rows.forEach(row => tbody.appendChild(row));
        });
    });
}

// ── Show Pipeline Not Run Notice ──
function showPipelineNotice() {
    const mainContent = document.querySelector('.main-content');
    if (!mainContent) return;

    // Hide all pages
    document.querySelectorAll('.page-section').forEach(p => p.style.display = 'none');

    const notice = document.createElement('div');
    notice.className = 'pipeline-notice';
    notice.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126z"/>
            <path d="M12 15.75h.007v.008H12v-.008z"/>
        </svg>
        <h2>Pipeline Not Yet Run</h2>
        <p>Train the models first by running the ML pipeline:</p>
        <p><code>python pipeline/run_pipeline.py</code></p>
        <p>Then restart the server to load the dashboard with real metrics.</p>
    `;
    mainContent.prepend(notice);
}

// ── Initialize Dashboard ──
async function initDashboard() {
    setupNavigation();
    setupModelSelector();
    setupCaptureControls();

    try {
        // Fetch metrics
        const metricsRes = await fetch('/api/metrics');
        if (metricsRes.status === 503) {
            showPipelineNotice();
            // Still start SSE for when pipeline completes
            return;
        }

        const metricsData = await metricsRes.json();
        if (metricsData.error) {
            showPipelineNotice();
            return;
        }

        AppState.metrics = metricsData;

        // Fetch capture status
        try {
            const statusRes = await fetch('/api/capture/status');
            const statusData = await statusRes.json();
            AppState.captureStatus = statusData.status;
            updateCaptureStatusUI();
        } catch (e) { /* ignore */ }

        // ── Initialize Charts ──

        // Overview page
        AppState.charts.overviewTimeline = initTimelineChart('overview-timeline-chart');

        // Dataset page
        if (metricsData.dataset_stats?.class_distribution) {
            initClassDistributionChart('class-dist-chart', metricsData.dataset_stats.class_distribution);
        }
        if (metricsData.dataset_stats?.attack_subtypes) {
            initAttackSubtypeChart('attack-subtype-chart', metricsData.dataset_stats.attack_subtypes);
        }
        populateDatasetStats(metricsData.dataset_stats || {});

        // Model Comparison page
        if (metricsData.models) {
            initModelComparisonChart('model-comparison-chart', metricsData.models);
            populateMetricsTable(metricsData);
        }
        if (metricsData.roc_data) {
            initROCChart('roc-chart', metricsData.roc_data);
        }
        if (metricsData.confusion_matrices) {
            buildConfusionMatrices('confusion-matrices', metricsData.confusion_matrices, metricsData.class_names || ['normal', 'dos', 'probe', 'r2l', 'u2r']);
        }

        // Live Monitor page
        AppState.charts.liveTimeline = initLiveTimelineChart('live-timeline-chart');
        AppState.charts.sessionDonut = initSessionDonutChart('session-donut-chart');
        AppState.charts.confidenceHist = initConfidenceHistogram('confidence-hist-chart');

        // Feature Analysis page
        if (metricsData.feature_importance?.random_forest) {
            initFeatureImportanceChart('rf-importance-chart', metricsData.feature_importance.random_forest, '#3fb950');
        }
        if (metricsData.feature_importance?.xgboost) {
            initFeatureImportanceChart('xgb-importance-chart', metricsData.feature_importance.xgboost, '#d29922');
        }
        populateFeatureSummary(metricsData.feature_importance);

        // Stat cards
        setBestModelF1(metricsData);
        updateStatCards();

        // Table sorting
        setupTableSorting();

        // Start SSE
        AppState.sseClient = initSSE();

    } catch (error) {
        console.error('Dashboard init error:', error);
        showPipelineNotice();
    }
}

// ── Boot ──
document.addEventListener('DOMContentLoaded', initDashboard);
