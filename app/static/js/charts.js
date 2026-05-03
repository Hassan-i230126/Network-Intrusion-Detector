/**
 * charts.js — Chart.js configuration and initialization functions.
 *
 * All chart instances share consistent dark-theme styling with
 * transparent backgrounds, Inter font, and semi-transparent fills.
 */

/* global Chart */

// ── Shared Chart Defaults ──
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.plugins.tooltip.backgroundColor = '#21262d';
Chart.defaults.plugins.tooltip.borderColor = '#30363d';
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.cornerRadius = 6;
Chart.defaults.plugins.tooltip.titleFont = { weight: '600' };

const COLORS = {
    blue: '#58a6ff',
    green: '#3fb950',
    yellow: '#d29922',
    red: '#f85149',
    purple: '#bc8cff',
    orange: '#f0883e',
    teal: '#39d2c0',
    pink: '#f778ba'
};

const CLASS_COLORS = {
    normal: COLORS.green,
    dos: COLORS.red,
    probe: COLORS.yellow,
    r2l: COLORS.purple,
    u2r: COLORS.orange
};

// ── Class Distribution Doughnut ──
function initClassDistributionChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const labels = Object.keys(data);
    const values = Object.values(data);
    const colors = labels.map(l => CLASS_COLORS[l] || COLORS.teal);

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                data: values,
                backgroundColor: colors.map(c => c + '99'),
                borderColor: colors,
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 12, font: { size: 11 } }
                }
            }
        }
    });
}

// ── Model Comparison Grouped Bar ──
function initModelComparisonChart(canvasId, metricsData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !metricsData) return null;

    const classNames = ['normal', 'dos', 'probe', 'r2l', 'u2r'];
    const modelNames = Object.keys(metricsData);
    const modelColors = [COLORS.blue, COLORS.green, COLORS.yellow, COLORS.red];

    const datasets = modelNames.map((model, i) => {
        const f1Data = classNames.map(cls => {
            const perClass = metricsData[model]?.per_class_f1 || {};
            return perClass[cls] || 0;
        });
        return {
            label: model.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase()),
            data: f1Data,
            backgroundColor: (modelColors[i] || COLORS.teal) + '99',
            borderColor: modelColors[i] || COLORS.teal,
            borderWidth: 1,
            borderRadius: 3
        };
    });

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: classNames.map(c => c.toUpperCase()),
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    max: 1,
                    grid: { color: '#30363d' },
                    ticks: { font: { size: 11 }, stepSize: 0.2 }
                }
            },
            plugins: {
                legend: { position: 'top' }
            }
        }
    });
}

// ── ROC Curves ──
function initROCChart(canvasId, rocData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !rocData) return null;

    const modelColors = {
        decision_tree: COLORS.blue,
        random_forest: COLORS.green,
        xgboost: COLORS.yellow,
        stacked: COLORS.red
    };

    const datasets = [];

    // Diagonal reference line
    datasets.push({
        label: 'Random (AUC = 0.50)',
        data: Array.from({length: 100}, (_, i) => ({x: i/99, y: i/99})),
        borderColor: '#484f58',
        borderDash: [5, 5],
        borderWidth: 1,
        pointRadius: 0,
        fill: false
    });

    for (const [model, data] of Object.entries(rocData)) {
        if (!data.fpr || !data.fpr.length) continue;
        const points = data.fpr.map((fpr, i) => ({x: fpr, y: data.tpr[i]}));
        const displayName = model.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase());
        datasets.push({
            label: `${displayName} (AUC = ${data.auc.toFixed(2)})`,
            data: points,
            borderColor: modelColors[model] || COLORS.teal,
            backgroundColor: 'transparent',
            borderWidth: 2,
            pointRadius: 0,
            tension: 0.3,
            fill: false
        });
    }

    return new Chart(ctx, {
        type: 'scatter',
        data: { datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            showLine: true,
            scales: {
                x: {
                    title: { display: true, text: 'False Positive Rate', color: '#8b949e' },
                    min: 0, max: 1,
                    grid: { color: '#30363d' }
                },
                y: {
                    title: { display: true, text: 'True Positive Rate', color: '#8b949e' },
                    min: 0, max: 1,
                    grid: { color: '#30363d' }
                }
            },
            plugins: {
                legend: { position: 'top', labels: { font: { size: 11 } } }
            }
        }
    });
}

// ── Feature Importance Horizontal Bar ──
function initFeatureImportanceChart(canvasId, data, color) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !data || !data.length) return null;

    // Reverse for horizontal bar (top feature at top)
    const reversed = [...data].reverse();
    const labels = reversed.map(d => d.feature);
    const values = reversed.map(d => d.importance);

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Importance',
                data: values,
                backgroundColor: color + '80',
                borderColor: color,
                borderWidth: 1,
                borderRadius: 3
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { font: { size: 10 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 10 } }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

// ── Timeline Chart (Live Updates) ──
function initTimelineChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total Flows/sec',
                    data: [],
                    borderColor: COLORS.blue,
                    backgroundColor: COLORS.blue + '20',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 2
                },
                {
                    label: 'Attacks/sec',
                    data: [],
                    borderColor: COLORS.red,
                    backgroundColor: COLORS.red + '20',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { maxTicksLimit: 10, font: { size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { font: { size: 10 } }
                }
            },
            plugins: {
                legend: { position: 'top', labels: { font: { size: 11 } } }
            },
            animation: { duration: 200 }
        }
    });

    return chart;
}

// ── Session Donut (Live Updates) ──
function initSessionDonutChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: [
                    COLORS.green + '99',
                    COLORS.red + '99',
                    COLORS.yellow + '99',
                    COLORS.purple + '99',
                    COLORS.orange + '99'
                ],
                borderColor: [
                    COLORS.green,
                    COLORS.red,
                    COLORS.yellow,
                    COLORS.purple,
                    COLORS.orange
                ],
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 10, font: { size: 10 } }
                }
            },
            animation: { duration: 300 }
        }
    });
}

// ── Confidence Histogram (Live Updates) ──
function initConfidenceHistogram(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const bins = ['0.50-0.55', '0.55-0.60', '0.60-0.65', '0.65-0.70',
                  '0.70-0.75', '0.75-0.80', '0.80-0.85', '0.85-0.90',
                  '0.90-0.95', '0.95-1.00'];

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: bins,
            datasets: [{
                label: 'Predictions',
                data: new Array(10).fill(0),
                backgroundColor: COLORS.blue + '80',
                borderColor: COLORS.blue,
                borderWidth: 1,
                borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 9 }, maxRotation: 45 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: '#30363d' },
                    ticks: { font: { size: 10 } }
                }
            },
            plugins: { legend: { display: false } },
            animation: { duration: 300 }
        }
    });
}

// ── Stacked Area Timeline for Live Monitor ──
function initLiveTimelineChart(canvasId) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'Normal', data: [], borderColor: COLORS.green, backgroundColor: COLORS.green + '30', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                { label: 'DoS', data: [], borderColor: COLORS.red, backgroundColor: COLORS.red + '30', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                { label: 'Probe', data: [], borderColor: COLORS.yellow, backgroundColor: COLORS.yellow + '30', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                { label: 'R2L', data: [], borderColor: COLORS.purple, backgroundColor: COLORS.purple + '30', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 },
                { label: 'U2R', data: [], borderColor: COLORS.orange, backgroundColor: COLORS.orange + '30', fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 10, font: { size: 10 } } },
                y: { stacked: true, beginAtZero: true, grid: { color: '#30363d' }, ticks: { font: { size: 10 } } }
            },
            plugins: { legend: { position: 'top', labels: { font: { size: 10 } } } },
            animation: { duration: 200 }
        }
    });
}

// ── Attack Sub-type Horizontal Bar ──
function initAttackSubtypeChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !data) return null;

    // Sort by count descending, take top 20
    const sorted = Object.entries(data)
        .filter(([k]) => k !== 'normal')
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);

    const labels = sorted.map(([k]) => k).reverse();
    const values = sorted.map(([, v]) => v).reverse();

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Count',
                data: values,
                backgroundColor: COLORS.red + '80',
                borderColor: COLORS.red,
                borderWidth: 1,
                borderRadius: 3
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { beginAtZero: true, grid: { color: '#30363d' }, ticks: { font: { size: 10 } } },
                y: { grid: { display: false }, ticks: { font: { size: 10 } } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

// ── Confusion Matrix (DOM, no canvas) ──
function buildConfusionMatrices(containerId, confData, classNames) {
    const container = document.getElementById(containerId);
    if (!container || !confData) return;
    container.innerHTML = '';

    const modelDisplay = {
        decision_tree: 'Decision Tree',
        random_forest: 'Random Forest',
        xgboost: 'XGBoost',
        stacked: 'Stacked Ensemble'
    };

    for (const [model, matrix] of Object.entries(confData)) {
        const card = document.createElement('div');
        card.className = 'confusion-matrix-card';

        const title = document.createElement('h4');
        title.textContent = modelDisplay[model] || model;
        card.appendChild(title);

        const table = document.createElement('table');
        table.className = 'cm-table';

        // Header row
        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        headerRow.innerHTML = '<th></th>';
        classNames.forEach(cls => {
            const th = document.createElement('th');
            th.textContent = cls.toUpperCase().substring(0, 4);
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        // Body rows
        const tbody = document.createElement('tbody');
        const totalPerRow = matrix.map(row => row.reduce((a, b) => a + b, 0));
        const maxVal = Math.max(...matrix.flat());

        matrix.forEach((row, i) => {
            const tr = document.createElement('tr');
            const labelTd = document.createElement('th');
            labelTd.textContent = classNames[i] ? classNames[i].toUpperCase().substring(0, 4) : i;
            labelTd.style.textAlign = 'right';
            tr.appendChild(labelTd);

            row.forEach((val) => {
                const td = document.createElement('td');
                const normalized = maxVal > 0 ? val / maxVal : 0;
                const pct = totalPerRow[i] > 0 ? ((val / totalPerRow[i]) * 100).toFixed(1) : '0.0';

                // Color gradient from bg to accent blue
                const r = Math.round(22 + (88 - 22) * normalized);
                const g = Math.round(27 + (166 - 27) * normalized);
                const b = Math.round(34 + (255 - 34) * normalized);
                td.style.backgroundColor = `rgba(${r}, ${g}, ${b}, ${0.2 + normalized * 0.6})`;
                td.style.color = normalized > 0.5 ? '#ffffff' : '#e6edf3';

                td.innerHTML = `<span class="cm-cell-count">${val}</span><span class="cm-cell-pct">${pct}%</span>`;
                tr.appendChild(td);
            });

            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        card.appendChild(table);
        container.appendChild(card);
    }
}
