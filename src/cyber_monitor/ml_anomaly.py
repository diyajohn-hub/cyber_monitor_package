import json
import socket
import time
import os
import threading
from collections import deque
from datetime import datetime

import numpy as np
import psutil
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------------
# Feature extractor (unchanged public API, still used by the example script)
# ---------------------------------------------------------------------------

class TelemetryFeatureExtractor:
    """
    Extracts numerical features from raw telemetry JSON logs for ML processing.
    """
    def __init__(self):
        self.feature_columns = ['cpu_percent', 'ram_percent', 'usb_count']

    def load_and_preprocess(self, json_file_path):
        import pandas as pd
        try:
            with open(json_file_path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return pd.DataFrame()
        if not isinstance(data, list):
            data = [data]
        df = pd.DataFrame(data)
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0
        if 'hostname' not in df.columns:
            df['hostname'] = 'local_system'
        df[self.feature_columns] = df[self.feature_columns].fillna(0.0)
        for col in self.feature_columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)
        return df

    def extract_host_vectors(self, df):
        if df.empty:
            return {}
        host_vectors = {}
        for hostname, group in df.groupby('hostname'):
            features = group[self.feature_columns].values
            host_vectors[hostname] = features
        return host_vectors


# ---------------------------------------------------------------------------
# Per-host anomaly detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Wraps an IsolationForest for a single host. Trains on a rolling window
    of baseline readings and predicts anomalies on new data.
    """
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.is_trained = False

    def train_baseline(self, feature_matrix):
        if len(feature_matrix) < 2:
            return
        self.model.fit(feature_matrix)
        self.is_trained = True

    def predict(self, live_features):
        if not self.is_trained:
            raise ValueError("Model must be trained before calling predict.")
        return self.model.predict(live_features)

    def score(self, live_features):
        if not self.is_trained:
            return 0.0
        return float(self.model.decision_function(live_features)[0])


# ---------------------------------------------------------------------------
# Shared state – the background thread writes here, the Flask route reads it
# ---------------------------------------------------------------------------

_ml_state_lock = threading.Lock()
_ml_state = {
    "timestamp": "",
    "phase": "Initialising",
    "hosts": {},
    "anomalies": [],
}

MIN_TRAINING_POINTS = 20   # ~100 seconds at 5-second intervals
ROLLING_WINDOW = 200       # keep last 200 readings per host
POLL_INTERVAL = 5          # seconds between readings
HISTORY_FILE = "mnt/master/anomaly_history.json"
HISTORY_BUFFER_SIZE = 500  # in-memory ring buffer size

# Persistent anomaly history — append-only ring buffer
_anomaly_history_lock = threading.Lock()
_anomaly_history: deque = deque(maxlen=HISTORY_BUFFER_SIZE)


def get_ml_state() -> dict:
    """Thread-safe getter called by the Flask route."""
    with _ml_state_lock:
        return json.loads(json.dumps(_ml_state))  # deep copy


def _set_ml_state(new_state: dict):
    """Thread-safe setter called by the background worker."""
    with _ml_state_lock:
        _ml_state.update(new_state)


def get_anomaly_history(limit: int = 200) -> list[dict]:
    """Thread-safe getter for the anomaly history buffer, called by Flask."""
    with _anomaly_history_lock:
        entries = list(_anomaly_history)
    # Return most recent first, capped at limit
    return list(reversed(entries[-limit:]))


def _capture_top_processes(count: int = 10) -> list[dict]:
    """Snapshot the top CPU-consuming processes right now."""
    rows = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            rows.append({
                'pid': info.get('pid'),
                'name': info.get('name') or 'Unknown',
                'cpu_percent': round(float(info.get('cpu_percent') or 0), 1),
                'memory_percent': round(float(info.get('memory_percent') or 0), 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    rows.sort(key=lambda r: r['cpu_percent'], reverse=True)
    return rows[:count]


def _append_to_history(entry: dict):
    """Append an anomaly record to both the in-memory buffer and the
    persistent JSON file.  The file is append-only so evidence is never
    lost even after the model retrains."""
    with _anomaly_history_lock:
        _anomaly_history.append(entry)

    # Persist to disk — read existing, append, write back
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as fh:
                history = json.load(fh)
            if not isinstance(history, list):
                history = []
        else:
            history = []
        history.append(entry)
        with open(HISTORY_FILE, 'w', encoding='utf-8') as fh:
            json.dump(history, fh, indent=2)
    except Exception as exc:
        print(f"[ML] Failed to persist anomaly history: {exc}")


def _load_history_from_disk():
    """Seed the in-memory buffer from the persistent file on startup."""
    if not os.path.exists(HISTORY_FILE):
        return
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as fh:
            history = json.load(fh)
        if isinstance(history, list):
            with _anomaly_history_lock:
                for entry in history[-HISTORY_BUFFER_SIZE:]:
                    _anomaly_history.append(entry)
        print(f"[ML] Loaded {len(_anomaly_history)} anomaly history entries from disk")
    except Exception as exc:
        print(f"[ML] Could not load anomaly history: {exc}")


# ---------------------------------------------------------------------------
# Background worker
# ---------------------------------------------------------------------------

def run_anomaly_monitor():
    """
    Background daemon that:
    1. Collects LOCAL telemetry every 5 seconds via psutil.
    2. Also ingests remote-agent data from mnt/master/log.json if present.
    3. Trains an IsolationForest baseline per host after MIN_TRAINING_POINTS.
    4. Scores every new reading and flags anomalies.
    5. Publishes stats to the shared _ml_state dict (read by Flask).
    """
    hostname = socket.gethostname()
    log_file = "mnt/master/log.json"
    anomalies_file = "mnt/master/anomalies.json"
    os.makedirs("mnt/master", exist_ok=True)

    # Seed in-memory history from any previous run
    _load_history_from_disk()

    # Rolling buffers: hostname -> deque of [cpu, ram, usb]
    buffers: dict[str, deque] = {}
    detectors: dict[str, AnomalyDetector] = {}

    print(f"[ML] Anomaly Monitor started – collecting from '{hostname}'")

    while True:
        try:
            time.sleep(POLL_INTERVAL)

            # ---- 1. Collect local telemetry ----------------------------
            cpu = round(psutil.cpu_percent(interval=0.3), 1)
            ram = round(psutil.virtual_memory().percent, 1)
            usb = 0  # placeholder; USB count is expensive to query

            if hostname not in buffers:
                buffers[hostname] = deque(maxlen=ROLLING_WINDOW)
                detectors[hostname] = AnomalyDetector(contamination=0.05)

            buffers[hostname].append([cpu, ram, usb])

            # ---- 2. (Optional) Ingest remote agent data ----------------
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        remote_data = json.load(f)
                    if not isinstance(remote_data, list):
                        remote_data = [remote_data]
                    for entry in remote_data:
                        h = entry.get("hostname", "unknown")
                        if h == hostname:
                            continue  # skip duplicates of ourself
                        if h not in buffers:
                            buffers[h] = deque(maxlen=ROLLING_WINDOW)
                            detectors[h] = AnomalyDetector(contamination=0.05)
                        buffers[h].append([
                            float(entry.get("cpu_percent", 0)),
                            float(entry.get("ram_percent", 0)),
                            int(entry.get("usb_count", 0)),
                        ])
                except Exception:
                    pass

            # ---- 3. Train / Predict per host ---------------------------
            hosts_stats = {}
            anomalies_detected = []

            for host, buf in buffers.items():
                n = len(buf)
                det = detectors[host]
                features = np.array(list(buf))
                latest = features[-1].reshape(1, -1)

                if n < MIN_TRAINING_POINTS:
                    # Still collecting baseline data
                    hosts_stats[host] = {
                        "status": "Collecting Baseline",
                        "trained": False,
                        "data_points": n,
                        "needed": MIN_TRAINING_POINTS,
                        "progress_pct": round(n / MIN_TRAINING_POINTS * 100),
                        "last_reading": {
                            "cpu": float(latest[0][0]),
                            "ram": float(latest[0][1]),
                            "usb": int(latest[0][2]),
                        },
                        "last_score": None,
                        "verdict": "N/A",
                    }
                    continue

                # Retrain every cycle on the full rolling window so the
                # baseline slowly adapts (online-ish learning).
                det.train_baseline(features)

                score = det.score(latest)
                pred = det.predict(latest)[0]
                verdict = "ANOMALY" if pred == -1 else "Normal"

                hosts_stats[host] = {
                    "status": "Active",
                    "trained": True,
                    "data_points": n,
                    "needed": MIN_TRAINING_POINTS,
                    "progress_pct": 100,
                    "last_reading": {
                        "cpu": float(latest[0][0]),
                        "ram": float(latest[0][1]),
                        "usb": int(latest[0][2]),
                    },
                    "last_score": round(score, 4),
                    "verdict": verdict,
                }

                if pred == -1:
                    anomaly_entry = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "hostname": host,
                        "features": {
                            "cpu_percent": float(latest[0][0]),
                            "ram_percent": float(latest[0][1]),
                            "usb_count": int(latest[0][2]),
                        },
                        "score": round(score, 4),
                        "top_processes": _capture_top_processes(10),
                    }
                    anomalies_detected.append(anomaly_entry)

                    # Persist to the append-only history log
                    _append_to_history(anomaly_entry)

            # ---- 4. Publish state --------------------------------------
            phase = "Active" if any(
                s.get("trained") for s in hosts_stats.values()
            ) else "Collecting Baseline"

            _set_ml_state({
                "timestamp": time.strftime("%H:%M:%S"),
                "phase": phase,
                "hosts": hosts_stats,
                "anomalies": anomalies_detected,
            })

            if anomalies_detected:
                with open(anomalies_file, 'w') as f:
                    json.dump(anomalies_detected, f)

        except Exception as e:
            print(f"[ML] Error in anomaly monitor: {e}")
