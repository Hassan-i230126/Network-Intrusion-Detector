"""
server.py — Flask backend with REST API and SSE streaming.

Serves the dashboard, provides model metrics, prediction endpoints,
and real-time traffic classification via Server-Sent Events.
"""

import os
import sys
import json
import time
import threading
from typing import Optional

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd

from capture.sniffer import NetworkSniffer
from pipeline.loader import CLASS_NAMES

# ── App Setup ──
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')
CORS(app)

# ── Global State ──
sniffer: Optional[NetworkSniffer] = None
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
RESULTS_DIR = os.path.join(PROJECT_ROOT, 'results')
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')


def get_sniffer() -> NetworkSniffer:
    """Get or create the global sniffer instance."""
    global sniffer
    if sniffer is None:
        sniffer = NetworkSniffer(
            models_dir=MODELS_DIR,
            data_dir=DATA_DIR
        )
    return sniffer


def models_exist() -> bool:
    """Check if trained models exist on disk."""
    return os.path.exists(os.path.join(MODELS_DIR, 'rf_model.pkl'))


# ── Routes ──

@app.route('/')
def index():
    """Serve the dashboard page."""
    return render_template('index.html')


@app.route('/api/metrics')
def get_metrics():
    """Return the full metrics JSON from the pipeline evaluation."""
    metrics_path = os.path.join(RESULTS_DIR, 'metrics.json')
    if not os.path.exists(metrics_path):
        return jsonify({'error': 'Pipeline not yet run'}), 503

    with open(metrics_path, 'r') as f:
        metrics = json.load(f)
    return jsonify(metrics)


@app.route('/api/models')
def get_models():
    """Return list of available trained models with their top-level metrics."""
    if not models_exist():
        return jsonify({'error': 'Pipeline not yet run'}), 503

    metrics_path = os.path.join(RESULTS_DIR, 'metrics.json')
    if not os.path.exists(metrics_path):
        return jsonify({'error': 'Pipeline not yet run'}), 503

    with open(metrics_path, 'r') as f:
        metrics = json.load(f)

    model_list = []
    model_display = {
        'decision_tree': {'name': 'Decision Tree', 'key': 'dt'},
        'random_forest': {'name': 'Random Forest', 'key': 'rf'},
        'xgboost': {'name': 'XGBoost', 'key': 'xgb'},
        'stacked': {'name': 'Stacked Ensemble', 'key': 'stacked'}
    }

    for model_id, display in model_display.items():
        if model_id in metrics.get('models', {}):
            m = metrics['models'][model_id]
            model_list.append({
                'id': display['key'],
                'name': display['name'],
                'accuracy': m.get('accuracy', 0),
                'f1_weighted': m.get('f1_weighted', 0),
                'roc_auc': m.get('roc_auc', 0)
            })

    return jsonify(model_list)


@app.route('/api/predict', methods=['POST'])
def predict():
    """Classify a single feature vector using the selected model."""
    if not models_exist():
        return jsonify({'error': 'Pipeline not yet run'}), 503

    data = request.get_json()
    if not data or 'features' not in data:
        return jsonify({'error': 'Missing features in request body'}), 400

    model_key = data.get('model', 'rf')
    model_map = {
        'dt': 'dt_model.pkl',
        'rf': 'rf_model.pkl',
        'xgb': 'xgb_model.pkl',
        'stacked': 'stack_model.pkl'
    }

    model_file = model_map.get(model_key, 'rf_model.pkl')
    model_path = os.path.join(MODELS_DIR, model_file)
    prep_path = os.path.join(MODELS_DIR, 'preprocessor.pkl')

    try:
        model = joblib.load(model_path)
        preprocessor = joblib.load(prep_path)

        from pipeline.preprocessor import add_engineered_features, CATEGORICAL_FEATURES

        df = pd.DataFrame([data['features']])
        df_eng = add_engineered_features(df)
        numerical_features = [
            f for f in df_eng.columns if f not in CATEGORICAL_FEATURES
        ]
        X = df_eng[CATEGORICAL_FEATURES + numerical_features]
        X_transformed = preprocessor.transform(X)

        clf = model
        if hasattr(clf, 'named_steps') and 'clf' in clf.named_steps:
            clf = clf.named_steps['clf']

        pred = clf.predict(X_transformed)[0]
        proba = clf.predict_proba(X_transformed)[0]

        prediction = CLASS_NAMES[int(pred)] if int(pred) < len(CLASS_NAMES) else 'unknown'
        probabilities = {CLASS_NAMES[i]: round(float(proba[i]), 4)
                        for i in range(min(len(CLASS_NAMES), len(proba)))}

        return jsonify({
            'prediction': prediction,
            'confidence': round(float(np.max(proba)), 4),
            'probabilities': probabilities,
            'model': model_key
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stream')
def stream():
    """Server-Sent Events endpoint for real-time traffic classification."""
    def event_stream():
        """Generate SSE events from the sniffer queue."""
        s = get_sniffer()
        while True:
            flow = s.get_flow(timeout=1.0)
            if flow:
                yield f"data: {json.dumps(flow)}\n\n"
            else:
                # Send keepalive comment to prevent connection timeout
                yield ": keepalive\n\n"

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )


@app.route('/api/capture/start')
def capture_start():
    """Start the network sniffer."""
    s = get_sniffer()
    if s.status != 'stopped':
        return jsonify({'status': s.status, 'message': 'Already running'})

    # Start in simulation mode by default (safe for all environments)
    s.start_sniffing(simulate=True)
    return jsonify({'status': 'started'})


@app.route('/api/capture/stop')
def capture_stop():
    """Stop the network sniffer."""
    s = get_sniffer()
    s.stop_sniffing()
    return jsonify({'status': 'stopped'})


@app.route('/api/capture/status')
def capture_status():
    """Return the current capture status."""
    s = get_sniffer()
    return jsonify({
        'status': s.status,
        'packets_processed': s.packets_processed
    })


@app.route('/api/capture/model', methods=['POST'])
def capture_model():
    """Switch the active model for live classification."""
    data = request.get_json()
    if not data or 'model' not in data:
        return jsonify({'error': 'Missing model in request body'}), 400

    model_key = data['model']
    s = get_sniffer()
    s.set_active_model(model_key)

    return jsonify({'active_model': model_key})


# ── Auto-start sniffer ──
def auto_start_sniffer():
    """Start the sniffer in simulation mode on app startup."""
    time.sleep(2)  # Wait for Flask to initialize
    if models_exist():
        s = get_sniffer()
        s.start_sniffing(simulate=True)
        print(" * Sniffer started in simulation mode")
    else:
        print(" * Models not found — sniffer not started. Run the pipeline first.")


if __name__ == '__main__':
    # Start sniffer in background
    startup_thread = threading.Thread(target=auto_start_sniffer, daemon=True)
    startup_thread.start()

    print("\n  NIDS Dashboard: http://localhost:5000\n")
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        use_reloader=False
    )
