"""
sniffer.py — Network traffic capture with live and simulation modes.

Uses Scapy for live packet sniffing or replays KDDTest+ rows in simulation mode.
Produces classified flows and pushes them to a thread-safe queue.
"""

import os
import sys
import time
import random
import threading
import queue
from datetime import datetime
from typing import Optional, Dict, Any, Callable

import numpy as np
import pandas as pd
import joblib

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from pipeline.loader import KDD_COLUMNS, ATTACK_MAPPING, CLASS_NAMES, CLASS_TO_INT


class NetworkSniffer:
    """Network traffic sniffer with live capture and simulation modes."""

    def __init__(self, models_dir: str = 'models', data_dir: str = 'data'):
        """Initialize the sniffer with model and data paths."""
        self._models_dir = models_dir
        self._data_dir = data_dir
        self._running = False
        self._simulate = False
        self._thread: Optional[threading.Thread] = None
        self._flow_queue: queue.Queue = queue.Queue(maxsize=1000)
        self._packets_processed = 0
        self._active_model_name = 'rf'
        self._model = None
        self._preprocessor = None
        self._test_data: Optional[pd.DataFrame] = None
        self._lock = threading.Lock()

    @property
    def status(self) -> str:
        """Return current capture status."""
        if not self._running:
            return 'stopped'
        return 'simulating' if self._simulate else 'running'

    @property
    def packets_processed(self) -> int:
        """Return total flows/packets processed."""
        return self._packets_processed

    def set_active_model(self, model_name: str) -> None:
        """Switch the active classification model."""
        with self._lock:
            self._active_model_name = model_name
            self._load_model()

    def _load_model(self) -> None:
        """Load the active model and preprocessor from disk."""
        model_map = {
            'dt': 'dt_model.pkl',
            'rf': 'rf_model.pkl',
            'xgb': 'xgb_model.pkl',
            'stacked': 'stack_model.pkl'
        }
        model_file = model_map.get(self._active_model_name, 'rf_model.pkl')
        model_path = os.path.join(self._models_dir, model_file)
        prep_path = os.path.join(self._models_dir, 'preprocessor.pkl')

        try:
            self._model = joblib.load(model_path)
            self._preprocessor = joblib.load(prep_path)
        except FileNotFoundError:
            self._model = None
            self._preprocessor = None

    def _load_test_data(self) -> None:
        """Load KDDTest+ for simulation mode."""
        test_path = os.path.join(self._data_dir, 'KDDTest+.txt')
        if os.path.exists(test_path):
            self._test_data = pd.read_csv(test_path, header=None, names=KDD_COLUMNS)
            self._test_data.drop('difficulty', axis=1, inplace=True)
            # Map labels
            self._test_data['attack_class'] = self._test_data['label'].map(ATTACK_MAPPING)
            self._test_data.loc[self._test_data['attack_class'].isna(), 'attack_class'] = 'dos'
            self._test_data['attack_class_int'] = self._test_data['attack_class'].map(CLASS_TO_INT)

    def _classify_row(self, row: pd.Series) -> Dict[str, Any]:
        """Classify a single data row using the active model."""
        if self._model is None or self._preprocessor is None:
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'probabilities': {}
            }

        try:
            from pipeline.preprocessor import add_engineered_features, CATEGORICAL_FEATURES

            # Build single-row DataFrame
            feature_cols = [c for c in row.index if c not in
                          ['label', 'binary_label', 'attack_class', 'attack_class_int']]
            df = pd.DataFrame([row[feature_cols]])
            df_eng = add_engineered_features(df)

            numerical_features = [
                f for f in df_eng.columns
                if f not in CATEGORICAL_FEATURES
            ]
            X = df_eng[CATEGORICAL_FEATURES + numerical_features]
            X_transformed = self._preprocessor.transform(X)

            # Get the classifier
            clf = self._model
            if hasattr(clf, 'named_steps') and 'clf' in clf.named_steps:
                clf = clf.named_steps['clf']

            # Predict
            pred = clf.predict(X_transformed)[0]
            proba = clf.predict_proba(X_transformed)[0]

            prediction = CLASS_NAMES[int(pred)] if int(pred) < len(CLASS_NAMES) else 'unknown'
            confidence = float(np.max(proba))
            probabilities = {}
            for i, cls in enumerate(CLASS_NAMES):
                if i < len(proba):
                    probabilities[cls] = round(float(proba[i]), 4)

            return {
                'prediction': prediction,
                'confidence': round(confidence, 4),
                'probabilities': probabilities
            }

        except Exception as e:
            return {
                'prediction': 'unknown',
                'confidence': 0.0,
                'probabilities': {}
            }

    def _generate_realistic_ip(self) -> str:
        """Generate a realistic private IP address."""
        subnet = random.choice(['192.168', '10.0'])
        if subnet == '192.168':
            return f"192.168.{random.randint(0, 10)}.{random.randint(1, 254)}"
        else:
            return f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}"

    def _simulation_worker(self) -> None:
        """Worker thread that replays KDDTest+ rows as simulated traffic."""
        if self._test_data is None:
            return

        indices = self._test_data.index.tolist()
        random.shuffle(indices)
        idx = 0

        while self._running:
            try:
                row = self._test_data.iloc[indices[idx % len(indices)]]
                idx += 1

                # Classify using the actual model
                result = self._classify_row(row)

                # Build the flow event
                src_ip = self._generate_realistic_ip()
                dst_ip = self._generate_realistic_ip()
                while dst_ip == src_ip:
                    dst_ip = self._generate_realistic_ip()

                event = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': random.randint(1024, 65535),
                    'dst_port': random.choice([80, 443, 22, 25, 53, 21, 23, 110, 143, 3306]),
                    'protocol': str(row.get('protocol_type', 'tcp')),
                    'service': str(row.get('service', 'http')),
                    'prediction': result['prediction'],
                    'confidence': result['confidence'],
                    'probabilities': result['probabilities'],
                    'duration': float(row.get('duration', 0)),
                    'src_bytes': int(row.get('src_bytes', 0)),
                    'dst_bytes': int(row.get('dst_bytes', 0)),
                    'flag': str(row.get('flag', 'SF')),
                    'actual_label': str(row.get('attack_class', 'unknown'))
                }

                # Put in queue (non-blocking, discard if full)
                try:
                    self._flow_queue.put_nowait(event)
                except queue.Full:
                    # Drop oldest and add new
                    try:
                        self._flow_queue.get_nowait()
                    except queue.Empty:
                        pass
                    self._flow_queue.put_nowait(event)

                with self._lock:
                    self._packets_processed += 1

                # Emit 2 records per second
                time.sleep(0.5)

            except Exception:
                time.sleep(1)
                continue

    def _live_capture_worker(self) -> None:
        """Worker thread for live packet capture using Scapy."""
        try:
            from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, conf
            from capture.feature_extractor import extract_features_from_packets, features_to_array

            flows = {}
            flow_lock = threading.Lock()

            def packet_callback(packet):
                """Process each captured packet."""
                try:
                    if not packet.haslayer(IP):
                        return

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if packet.haslayer(TCP):
                        protocol = 'tcp'
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                    elif packet.haslayer(UDP):
                        protocol = 'udp'
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                    else:
                        protocol = 'icmp'
                        src_port = 0
                        dst_port = 0

                    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

                    with flow_lock:
                        if flow_key not in flows:
                            flows[flow_key] = {
                                'packets': [],
                                'start_time': time.time(),
                                'meta': {
                                    'src_ip': src_ip, 'dst_ip': dst_ip,
                                    'src_port': src_port, 'dst_port': dst_port,
                                    'protocol': protocol
                                }
                            }

                        flows[flow_key]['packets'].append(packet)

                        # Check flow completion
                        flow = flows[flow_key]
                        complete = False

                        if packet.haslayer(TCP):
                            flags = str(packet[TCP].flags)
                            if 'F' in flags or 'R' in flags:
                                complete = True

                        if len(flow['packets']) > 100:
                            complete = True

                        if time.time() - flow['start_time'] > 5:
                            complete = True

                        if complete:
                            completed_flow = flows.pop(flow_key)
                            self._process_completed_flow(completed_flow)

                except Exception:
                    pass

            sniffer = AsyncSniffer(
                prn=packet_callback,
                store=False,
                iface=conf.iface
            )
            sniffer.start()

            while self._running:
                # Check for timed-out flows
                with flow_lock:
                    now = time.time()
                    expired = [k for k, v in flows.items()
                             if now - v['start_time'] > 5]
                    for k in expired:
                        completed = flows.pop(k)
                        self._process_completed_flow(completed)
                time.sleep(1)

            sniffer.stop()

        except (PermissionError, OSError, Exception):
            # Fall back to simulation mode
            self._simulate = True
            self._simulation_worker()

    def _process_completed_flow(self, flow_data: Dict) -> None:
        """Process a completed flow through feature extraction and classification."""
        try:
            from capture.feature_extractor import extract_features_from_packets, features_to_array

            features = extract_features_from_packets(
                flow_data['packets'], flow_data['meta']
            )
            if features is None:
                return

            X = features_to_array(features)
            if X is None:
                return

            clf = self._model
            if hasattr(clf, 'named_steps') and 'clf' in clf.named_steps:
                clf = clf.named_steps['clf']

            pred = clf.predict(X)[0]
            proba = clf.predict_proba(X)[0]

            prediction = CLASS_NAMES[int(pred)] if int(pred) < len(CLASS_NAMES) else 'unknown'

            meta = flow_data['meta']
            event = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': meta['src_ip'],
                'dst_ip': meta['dst_ip'],
                'src_port': meta['src_port'],
                'dst_port': meta['dst_port'],
                'protocol': meta['protocol'],
                'service': features.get('service', 'other'),
                'prediction': prediction,
                'confidence': round(float(np.max(proba)), 4),
                'probabilities': {CLASS_NAMES[i]: round(float(proba[i]), 4)
                                 for i in range(min(len(CLASS_NAMES), len(proba)))},
                'duration': features.get('duration', 0),
                'src_bytes': features.get('src_bytes', 0),
                'dst_bytes': features.get('dst_bytes', 0),
            }

            try:
                self._flow_queue.put_nowait(event)
            except queue.Full:
                try:
                    self._flow_queue.get_nowait()
                except queue.Empty:
                    pass
                self._flow_queue.put_nowait(event)

            with self._lock:
                self._packets_processed += 1

        except Exception:
            pass

    def start_sniffing(self, simulate: bool = False) -> None:
        """Start the network sniffer in either live or simulation mode."""
        if self._running:
            return

        self._running = True
        self._load_model()

        if simulate or os.environ.get('SIMULATE', '').lower() == 'true':
            self._simulate = True
            self._load_test_data()
            self._thread = threading.Thread(
                target=self._simulation_worker, daemon=True
            )
        else:
            self._simulate = False
            self._thread = threading.Thread(
                target=self._live_capture_worker, daemon=True
            )

        self._thread.start()

    def stop_sniffing(self) -> None:
        """Stop the network sniffer."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    def get_flow(self, timeout: float = 1.0) -> Optional[Dict]:
        """Get the next classified flow from the queue."""
        try:
            return self._flow_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_flow_nowait(self) -> Optional[Dict]:
        """Get a flow without blocking."""
        try:
            return self._flow_queue.get_nowait()
        except queue.Empty:
            return None
