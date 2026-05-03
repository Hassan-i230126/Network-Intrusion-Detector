/**
 * realtime.js — SSE client for live traffic data streaming.
 *
 * Opens an EventSource to /api/stream and updates all live dashboard
 * components: counters, feeds, charts, tables, and alerts.
 */

/* global AppState */

let _eventSource = null;
let _reconnectTimeout = null;
let _timelineBuffer = { total: 0, attacks: 0 };
let _timelineInterval = null;
let _confidenceUpdateInterval = null;
let _confidenceData = [];
let _liveTimelineCounts = { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 };

// ── Animated Number Counter ──
function animateCounter(element, targetValue) {
    if (!element) return;
    const current = parseInt(element.textContent.replace(/,/g, '')) || 0;
    const diff = targetValue - current;
    if (diff === 0) return;

    const startTime = performance.now();
    const duration = 300;

    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const val = Math.round(current + diff * eased);
        element.textContent = val.toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

// ── Update Overview Stat Cards ──
function updateStatCards() {
    animateCounter(document.getElementById('stat-total-records'), AppState.totalFlows);
    animateCounter(document.getElementById('stat-attacks-detected'),
        AppState.totalFlows - AppState.sessionCounts.normal);

    const activeModelEl = document.getElementById('stat-active-model');
    if (activeModelEl) {
        const modelNames = { dt: 'Decision Tree', rf: 'Random Forest', xgb: 'XGBoost', stacked: 'Stacked' };
        activeModelEl.textContent = modelNames[AppState.activeModel] || AppState.activeModel;
    }
}

// ── Update Events Feed ──
function updateEventsFeed(event) {
    const feed = document.getElementById('events-feed-list');
    if (!feed) return;

    const row = document.createElement('div');
    row.className = 'event-row';
    if (event.prediction !== 'normal') {
        row.classList.add('flash-attack');
    }

    const time = new Date(event.timestamp);
    const timeStr = time.toLocaleTimeString('en-US', { hour12: false });

    row.innerHTML = `
        <span class="event-time">${timeStr}</span>
        <span class="event-ips">${event.src_ip} → ${event.dst_ip}</span>
        <span class="event-service">${event.service}</span>
        <span class="badge badge-${event.prediction}">${event.prediction}</span>
    `;

    feed.prepend(row);

    // Keep max 20 rows
    while (feed.children.length > 20) {
        feed.removeChild(feed.lastChild);
    }
}

// ── Update Live Traffic Table ──
function updateTrafficTable(event) {
    const tbody = document.getElementById('live-traffic-tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    if (event.prediction !== 'normal') {
        row.classList.add('flash-attack');
    }

    const time = new Date(event.timestamp);
    const timeStr = time.toLocaleTimeString('en-US', { hour12: false });
    const confidence = (event.confidence * 100).toFixed(1);

    row.innerHTML = `
        <td>${timeStr}</td>
        <td>${event.src_ip}</td>
        <td>${event.dst_ip}</td>
        <td>${event.service}</td>
        <td>${event.protocol}</td>
        <td>${event.src_bytes + event.dst_bytes}</td>
        <td><span class="badge badge-${event.prediction}">${event.prediction}</span></td>
        <td>${confidence}%</td>
    `;

    tbody.prepend(row);

    // Cap at 200 rows
    while (tbody.children.length > 200) {
        tbody.removeChild(tbody.lastChild);
    }
}

// ── Update Alert Panel ──
function updateAlertPanel(event) {
    if (event.prediction === 'normal') return;

    const panel = document.getElementById('alert-panel-list');
    if (!panel) return;

    const card = document.createElement('div');
    card.className = 'alert-card';

    const time = new Date(event.timestamp);
    const timeStr = time.toLocaleTimeString('en-US', { hour12: false });

    card.innerHTML = `
        <div class="alert-type">${event.prediction.toUpperCase()} Attack</div>
        <div class="alert-detail">${event.src_ip} → ${event.dst_ip}</div>
        <div class="alert-confidence">Confidence: ${(event.confidence * 100).toFixed(1)}% — ${timeStr}</div>
    `;

    panel.prepend(card);

    // Keep max 5 alerts
    while (panel.children.length > 5) {
        panel.removeChild(panel.lastChild);
    }
}

// ── Update Timeline Charts ──
function startTimelineUpdater() {
    if (_timelineInterval) return;

    _timelineInterval = setInterval(() => {
        // Overview timeline
        if (AppState.charts.overviewTimeline) {
            const chart = AppState.charts.overviewTimeline;
            const now = new Date().toLocaleTimeString('en-US', { hour12: false });

            chart.data.labels.push(now);
            chart.data.datasets[0].data.push(_timelineBuffer.total);
            chart.data.datasets[1].data.push(_timelineBuffer.attacks);

            // Keep last 60 seconds
            if (chart.data.labels.length > 60) {
                chart.data.labels.shift();
                chart.data.datasets.forEach(ds => ds.data.shift());
            }

            chart.update('none');
            _timelineBuffer = { total: 0, attacks: 0 };
        }

        // Live monitor timeline
        if (AppState.charts.liveTimeline) {
            const chart = AppState.charts.liveTimeline;
            const now = new Date().toLocaleTimeString('en-US', { hour12: false });

            chart.data.labels.push(now);
            const classes = ['normal', 'dos', 'probe', 'r2l', 'u2r'];
            classes.forEach((cls, i) => {
                chart.data.datasets[i].data.push(_liveTimelineCounts[cls]);
            });

            // Keep last 120 seconds
            if (chart.data.labels.length > 120) {
                chart.data.labels.shift();
                chart.data.datasets.forEach(ds => ds.data.shift());
            }

            chart.update('none');
            _liveTimelineCounts = { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 };
        }
    }, 1000);
}

// ── Confidence Histogram Updater ──
function startConfidenceUpdater() {
    if (_confidenceUpdateInterval) return;

    _confidenceUpdateInterval = setInterval(() => {
        if (!AppState.charts.confidenceHist) return;

        const bins = new Array(10).fill(0);
        _confidenceData.forEach(conf => {
            const idx = Math.min(Math.floor((conf - 0.5) / 0.05), 9);
            if (idx >= 0 && idx < 10) bins[idx]++;
        });

        AppState.charts.confidenceHist.data.datasets[0].data = bins;
        AppState.charts.confidenceHist.update('none');
    }, 5000);
}

// ── SSE Event Handler ──
function handleSSEEvent(event) {
    try {
        const data = JSON.parse(event.data);

        // Update AppState
        AppState.totalFlows++;
        if (data.prediction && data.prediction in AppState.sessionCounts) {
            AppState.sessionCounts[data.prediction]++;
        }
        AppState.recentFlows.unshift(data);
        if (AppState.recentFlows.length > 200) {
            AppState.recentFlows.pop();
        }

        // Timeline buffer
        _timelineBuffer.total++;
        if (data.prediction !== 'normal') {
            _timelineBuffer.attacks++;
        }

        // Live timeline counts
        if (data.prediction in _liveTimelineCounts) {
            _liveTimelineCounts[data.prediction]++;
        }

        // Confidence data
        if (data.confidence >= 0.5) {
            _confidenceData.push(data.confidence);
            if (_confidenceData.length > 1000) _confidenceData.shift();
        }

        // Update UI components
        updateStatCards();
        updateEventsFeed(data);

        // Update session donut
        if (AppState.charts.sessionDonut) {
            const counts = ['normal', 'dos', 'probe', 'r2l', 'u2r'].map(
                cls => AppState.sessionCounts[cls]
            );
            AppState.charts.sessionDonut.data.datasets[0].data = counts;
            AppState.charts.sessionDonut.update('none');
        }

        // Update live monitor if on that page
        const livePage = document.getElementById('page-live');
        if (livePage && livePage.classList.contains('active')) {
            updateTrafficTable(data);
        }

        // Alert panel
        updateAlertPanel(data);

        // Update packets count in status bar
        const pktsEl = document.getElementById('live-packets-count');
        if (pktsEl) pktsEl.textContent = AppState.totalFlows.toLocaleString();

    } catch (e) {
        console.error('SSE parse error:', e);
    }
}

// ── Init SSE ──
function initSSE() {
    if (_eventSource) {
        _eventSource.close();
    }

    _eventSource = new EventSource('/api/stream');

    _eventSource.onmessage = handleSSEEvent;

    _eventSource.onerror = (err) => {
        console.warn('SSE connection error, reconnecting in 3s...');
        showToast('Connection lost. Reconnecting...', 'warning');
        _eventSource.close();

        if (_reconnectTimeout) clearTimeout(_reconnectTimeout);
        _reconnectTimeout = setTimeout(() => {
            initSSE();
        }, 3000);
    };

    _eventSource.onopen = () => {
        console.log('SSE connected');
    };

    // Start periodic updaters
    startTimelineUpdater();
    startConfidenceUpdater();

    return {
        stop() {
            if (_eventSource) _eventSource.close();
            if (_timelineInterval) clearInterval(_timelineInterval);
            if (_confidenceUpdateInterval) clearInterval(_confidenceUpdateInterval);
            if (_reconnectTimeout) clearTimeout(_reconnectTimeout);
        }
    };
}

// ── Toast Notification ──
function showToast(message, type = 'info') {
    // Remove existing toast
    const existing = document.querySelector('.toast-notification');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'toast-notification';
    toast.style.cssText = `
        position: fixed; bottom: 20px; right: 20px; z-index: 1000;
        padding: 10px 20px; border-radius: 8px; font-size: 0.8125rem;
        background: #21262d; border: 1px solid #30363d;
        color: ${type === 'warning' ? '#d29922' : '#e6edf3'};
        animation: slideIn 300ms ease;
        font-family: 'Inter', system-ui, sans-serif;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 300ms ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
