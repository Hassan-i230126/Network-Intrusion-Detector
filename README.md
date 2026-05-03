# Network Intrusion Detection System (NIDS)

A production-quality Network Intrusion Detection System that combines a rigorous machine learning pipeline with a real-time traffic monitoring dashboard. The system trains multiple classifiers (Decision Tree, Random Forest, XGBoost, and a Stacked Ensemble) on the NSL-KDD dataset, evaluates them comprehensively, and deploys the best model behind a Flask API with a live traffic classification dashboard.

This project demonstrates the full ML lifecycle — from data loading and preprocessing through model training, hyperparameter tuning, and evaluation, to a polished web-based interface that classifies network flows in real time using either live packet capture (via Scapy) or a built-in simulation mode that replays real test data. The dashboard provides interactive visualizations of model performance, feature importance, dataset statistics, and a live monitor with streaming predictions.

## Dataset

This project uses the **NSL-KDD** dataset, an improved version of the original KDD Cup 1999 dataset. Download it from the [UNB Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/nsl.html).

Required files:
- `KDDTrain+.txt` (125,973 records)
- `KDDTest+.txt` (22,544 records)

Place both files in the `data/` directory.

## Installation

```bash
pip install -r requirements.txt
```

## Pipeline Execution

Train all models and generate evaluation metrics:

```bash
python pipeline/run_pipeline.py
```

**Expected runtime:** ~10–15 minutes on a laptop CPU. The pipeline will:
1. Load and parse the NSL-KDD dataset
2. Preprocess features (encoding, scaling, feature engineering)
3. Train 4 models with GridSearchCV hyperparameter tuning
4. Evaluate on the held-out test set and save all artifacts

All trained models are saved to `models/` and metrics to `results/metrics.json`.

## Start the Dashboard

```bash
python app/server.py
```

> **Note:** On Linux/Mac, run with `sudo` for live packet capture, or the system auto-falls back to simulation mode. On Windows, simulation mode is used by default.

Open your browser at **http://localhost:5000**

## Dashboard Pages

| Page | Description |
|------|-------------|
| **Overview** | Live counters, attack rate chart, recent events feed |
| **Dataset** | Class distribution, attack sub-types, dataset description |
| **Model Comparison** | Metrics table, F1 per class, ROC curves, confusion matrices |
| **Live Monitor** | Real-time traffic timeline, classification table, alerts |
| **Feature Analysis** | Top-20 feature importance for RF and XGBoost |

## Project Structure

```
nids_project/
├── data/                  # NSL-KDD dataset files
├── models/                # Serialized .pkl model files
├── results/               # metrics.json and plots
├── pipeline/
│   ├── loader.py          # Dataset loading and label mapping
│   ├── preprocessor.py    # Feature engineering and sklearn Pipeline
│   ├── trainer.py         # Model training with GridSearchCV + SMOTE
│   ├── evaluator.py       # Comprehensive model evaluation
│   └── run_pipeline.py    # Main entry point
├── capture/
│   ├── sniffer.py         # Live/simulated packet capture
│   └── feature_extractor.py  # KDD feature extraction
├── app/
│   ├── server.py          # Flask backend with SSE
│   ├── static/css/main.css
│   ├── static/js/
│   │   ├── dashboard.js   # Main application logic
│   │   ├── charts.js      # Chart.js configurations
│   │   └── realtime.js    # SSE client for live streaming
│   └── templates/
│       └── index.html     # Single-page dashboard
└── requirements.txt
```
