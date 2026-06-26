import json
import logging
import socket
import time
import os
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

import numpy as np
import psutil
from sklearn.ensemble import IsolationForest

import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv
from torch_geometric.data import Data
from torch_geometric.utils import to_dense_adj
import optuna

from cyber_monitor.network import get_live_connections

# Suppress Optuna's verbose INFO logs – only show warnings and errors
optuna.logging.set_verbosity(optuna.logging.WARNING)


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
# Network GNN Anomaly Detector — PyTorch Geometric + Optuna
# ---------------------------------------------------------------------------

class PyGGraphAutoencoder(torch.nn.Module):
    """
    PyTorch Geometric GCN Autoencoder.

    Encoder : two GCNConv layers producing a low-dimensional node embedding Z.
    Decoder : inner-product  →  A_pred = σ(Z·Zᵀ)

    Used to learn the "normal" network topology so that unknown or unusual
    edges produce a high reconstruction error.
    """

    def __init__(self, input_dim: int, hidden_dim: int = 16, latent_dim: int = 8):
        super().__init__()
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.conv1 = GCNConv(input_dim, hidden_dim)
        self.conv2 = GCNConv(hidden_dim, latent_dim)

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = F.relu(self.conv1(x, edge_index))
        z = self.conv2(h, edge_index)
        return z

    def decode(self, z: torch.Tensor) -> torch.Tensor:
        return torch.sigmoid(z @ z.t())

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        z = self.encode(x, edge_index)
        return self.decode(z)


# Resolve model checkpoint path (same directory as anomaly_history.json)
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
_MODEL_SAVE_PATH = str(_PACKAGE_ROOT / "mnt" / "master" / "gnn_model.pt")


class PyGNetworkAnomalyDetector:
    """
    Uses a PyG GCN Autoencoder to learn the normal topology of network
    connections.  New / unknown edges get a high reconstruction error and
    are flagged as anomalies.

    Optuna is used to tune hidden_dim, latent_dim, learning-rate and epoch
    count each time the model retrains.  The best model is checkpointed to
    disk so it survives application restarts.
    """

    # Optuna budget – keep lightweight for a background daemon
    OPTUNA_N_TRIALS = 10
    OPTUNA_TIMEOUT_S = 20

    def __init__(self, threshold: float = 0.65):
        self.model: PyGGraphAutoencoder | None = None
        self.trained_node_to_idx: dict[str, int] = {}
        self.trained_adj: np.ndarray | None = None
        self.threshold = threshold
        self.is_trained = False
        self.best_params: dict | None = None
        self.best_loss: float | None = None

    # ------------------------------------------------------------------
    # Graph building helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_pyg_data(
        connections: list[dict],
        node_map: dict[str, int] | None = None,
    ) -> tuple[Data, dict[str, int], np.ndarray]:
        """
        Convert a flat list of connection dicts into a PyG ``Data`` object.

        Returns
        -------
        data : torch_geometric.data.Data
            Graph with identity node features and undirected edge_index.
        node_to_idx : dict
            IP → integer index mapping.
        A : np.ndarray
            Dense adjacency matrix (kept for scoring convenience).
        """
        if node_map is None:
            nodes = set()
            for c in connections:
                nodes.add(c["local_ip"])
                nodes.add(c["remote_ip"])
            nodes_sorted = sorted(nodes)
            node_to_idx = {n: i for i, n in enumerate(nodes_sorted)}
        else:
            node_to_idx = node_map

        N = len(node_to_idx)
        if N == 0:
            empty = Data(
                x=torch.zeros((0, 0)),
                edge_index=torch.zeros((2, 0), dtype=torch.long),
            )
            return empty, {}, np.zeros((0, 0))

        # Build edge list (undirected)
        edge_set: set[tuple[int, int]] = set()
        A = np.zeros((N, N))
        for c in connections:
            u_ip, v_ip = c["local_ip"], c["remote_ip"]
            if u_ip in node_to_idx and v_ip in node_to_idx:
                u, v = node_to_idx[u_ip], node_to_idx[v_ip]
                edge_set.add((u, v))
                edge_set.add((v, u))
                A[u, v] = 1.0
                A[v, u] = 1.0

        if edge_set:
            src, dst = zip(*edge_set)
            edge_index = torch.tensor([src, dst], dtype=torch.long)
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        # Identity features (one-hot per node) — topology-only signal
        x = torch.eye(N, dtype=torch.float32)

        data = Data(x=x, edge_index=edge_index)
        return data, node_to_idx, A

    # ------------------------------------------------------------------
    # Optuna objective
    # ------------------------------------------------------------------

    def _optuna_objective(
        self,
        trial: optuna.Trial,
        data: Data,
        target_adj: torch.Tensor,
    ) -> float:
        """Single Optuna trial: build, train, return reconstruction loss."""
        N = int(data.x.shape[0])
        hidden_dim = trial.suggest_int("hidden_dim", 4, max(6, min(N, 32)))
        latent_dim = trial.suggest_int("latent_dim", 2, max(3, hidden_dim))
        lr = trial.suggest_float("lr", 1e-4, 0.1, log=True)
        epochs = trial.suggest_int("epochs", 10, 50)

        model = PyGGraphAutoencoder(N, hidden_dim, latent_dim)
        optimiser = torch.optim.Adam(model.parameters(), lr=lr)

        model.train()
        for _ in range(epochs):
            optimiser.zero_grad()
            a_pred = model(data.x, data.edge_index)
            loss = F.binary_cross_entropy(a_pred, target_adj)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optimiser.step()

        model.eval()
        with torch.no_grad():
            a_pred = model(data.x, data.edge_index)
            final_loss = F.binary_cross_entropy(a_pred, target_adj).item()

        return final_loss

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train_baseline(self, historical_connections_lists: list[list[dict]]):
        """
        Train on merged historical snapshots.

        1. Build a PyG graph from all observed connections.
        2. Run an Optuna study to find the best hyperparameters.
        3. Train the final model with those hyperparameters.
        4. Checkpoint to disk.
        """
        if not historical_connections_lists:
            return

        all_conns: list[dict] = []
        for conns in historical_connections_lists:
            all_conns.extend(conns)
        if not all_conns:
            return

        data, node_to_idx, A = self._build_pyg_data(all_conns)
        N = len(node_to_idx)
        if N < 2:
            return

        self.trained_node_to_idx = dict(node_to_idx)
        self.trained_adj = A.copy()

        target_adj = torch.tensor(A, dtype=torch.float32)

        # --- Optuna hyperparameter search --------------------------------
        study = optuna.create_study(direction="minimize")
        try:
            study.optimize(
                lambda trial: self._optuna_objective(trial, data, target_adj),
                n_trials=self.OPTUNA_N_TRIALS,
                timeout=self.OPTUNA_TIMEOUT_S,
                show_progress_bar=False,
            )
            best = study.best_params
            self.best_loss = study.best_value
        except Exception as exc:
            print(f"[ML/GNN] Optuna study failed ({exc}), using defaults")
            best = {"hidden_dim": max(4, N // 3), "latent_dim": max(2, N // 6),
                    "lr": 0.01, "epochs": 30}
            self.best_loss = None

        self.best_params = best
        print(f"[ML/GNN] Optuna best params: {best}  (loss={self.best_loss})")

        # --- Train final model with best params --------------------------
        hidden_dim = best.get("hidden_dim", 16)
        latent_dim = best.get("latent_dim", 8)
        lr = best.get("lr", 0.01)
        epochs = best.get("epochs", 30)

        self.model = PyGGraphAutoencoder(N, hidden_dim, latent_dim)
        optimiser = torch.optim.Adam(self.model.parameters(), lr=lr)

        self.model.train()
        for epoch in range(epochs):
            optimiser.zero_grad()
            a_pred = self.model(data.x, data.edge_index)
            loss = F.binary_cross_entropy(a_pred, target_adj)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 5.0)
            optimiser.step()

        self.model.eval()
        self.is_trained = True

        # --- Persist model checkpoint ------------------------------------
        try:
            os.makedirs(os.path.dirname(_MODEL_SAVE_PATH), exist_ok=True)
            torch.save({
                "state_dict": self.model.state_dict(),
                "node_to_idx": self.trained_node_to_idx,
                "best_params": self.best_params,
                "best_loss": self.best_loss,
                "input_dim": N,
                "hidden_dim": hidden_dim,
                "latent_dim": latent_dim,
            }, _MODEL_SAVE_PATH)
            print(f"[ML/GNN] Model checkpoint saved -> {_MODEL_SAVE_PATH}")
        except Exception as exc:
            print(f"[ML/GNN] Could not save model checkpoint: {exc}")

    # ------------------------------------------------------------------
    # Loading a saved model (called once at startup)
    # ------------------------------------------------------------------

    def try_load_checkpoint(self):
        """Attempt to restore a previously-saved model from disk."""
        if not os.path.exists(_MODEL_SAVE_PATH):
            return
        try:
            ckpt = torch.load(_MODEL_SAVE_PATH, map_location="cpu", weights_only=False)
            N = ckpt["input_dim"]
            self.model = PyGGraphAutoencoder(
                N, ckpt["hidden_dim"], ckpt["latent_dim"]
            )
            self.model.load_state_dict(ckpt["state_dict"])
            self.model.eval()
            self.trained_node_to_idx = ckpt["node_to_idx"]
            self.best_params = ckpt.get("best_params")
            self.best_loss = ckpt.get("best_loss")
            self.is_trained = True
            print(f"[ML/GNN] Restored model checkpoint ({N} nodes) from {_MODEL_SAVE_PATH}")
        except Exception as exc:
            print(f"[ML/GNN] Could not load checkpoint: {exc}")

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score_connections(self, live_connections: list[dict]) -> list[dict]:
        """Score each live connection.  Unknown edges → anomaly."""
        if not self.is_trained or self.model is None:
            return [dict(c, anomaly_score=0.0, is_anomaly=False) for c in live_connections]

        # Build a PyG graph using the TRAINED node mapping so dimensions
        # match the model weights.
        data, _, _ = self._build_pyg_data(
            live_connections, node_map=self.trained_node_to_idx
        )

        self.model.eval()
        with torch.no_grad():
            a_pred = self.model(data.x, data.edge_index)  # (N, N)

        a_pred_np = a_pred.numpy()

        scored = []
        for c in live_connections:
            u_ip, v_ip = c["local_ip"], c["remote_ip"]

            if u_ip in self.trained_node_to_idx and v_ip in self.trained_node_to_idx:
                u = self.trained_node_to_idx[u_ip]
                v = self.trained_node_to_idx[v_ip]
                pred_edge = float(a_pred_np[u, v])
                score = round(1.0 - pred_edge, 4)
            else:
                # Completely new IP not seen during training → anomaly
                score = 1.0

            c_copy = dict(c)
            c_copy["anomaly_score"] = score
            c_copy["is_anomaly"] = score > self.threshold
            scored.append(c_copy)

        return scored

    # ------------------------------------------------------------------
    # Info dict (published in ML state for optional frontend display)
    # ------------------------------------------------------------------

    def get_gnn_info(self) -> dict:
        """Return a serialisable summary of the current GNN state."""
        return {
            "backend": "PyTorch Geometric",
            "is_trained": self.is_trained,
            "best_params": self.best_params,
            "best_loss": round(self.best_loss, 6) if self.best_loss is not None else None,
            "optuna_trials": self.OPTUNA_N_TRIALS,
            "node_count": len(self.trained_node_to_idx),
        }


# ---------------------------------------------------------------------------
# Shared state – the background thread writes here, the Flask route reads it
# ---------------------------------------------------------------------------

_ml_state_lock = threading.Lock()
_ml_state = {
    "timestamp": "",
    "phase": "Initialising",
    "hosts": {},
    "anomalies": [],
    "new_processes": [],
    "network_graph": {"nodes": [], "edges": []},
}

_reset_gnn_flag_lock = threading.Lock()
_reset_gnn_flag = False

def reset_network_graph():
    """Signal the background worker to reset the GNN model and network graph."""
    global _reset_gnn_flag
    with _reset_gnn_flag_lock:
        _reset_gnn_flag = True

MIN_TRAINING_POINTS = 20   # ~100 seconds at 5-second intervals
ROLLING_WINDOW = 200       # keep last 200 readings per host
POLL_INTERVAL = 5          # seconds between readings
HISTORY_BUFFER_SIZE = 500  # in-memory ring buffer size

# Resolve paths relative to the project root (same strategy as server.py)
PACKAGE_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR      = PACKAGE_ROOT / "mnt"
MASTER_DIR   = LOG_DIR / "master"
HISTORY_FILE = str(MASTER_DIR / "anomaly_history.json")

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
    log_file = str(MASTER_DIR / "log.json")
    anomalies_file = str(MASTER_DIR / "anomalies.json")
    MASTER_DIR.mkdir(parents=True, exist_ok=True)

    # Seed in-memory history from any previous run
    _load_history_from_disk()

    buffers: dict[str, deque] = {}
    detectors: dict[str, AnomalyDetector] = {}

    local_known_processes = set()
    new_processes_log_file = str(MASTER_DIR / "new_processes.json")

    net_detector = PyGNetworkAnomalyDetector()
    net_detector.try_load_checkpoint()          # restore from disk if available
    net_buffer = deque(maxlen=ROLLING_WINDOW)
    network_graph = {"nodes": [], "edges": []}

    known_network_nodes = set()
    new_network_nodes_log_file = str(MASTER_DIR / "new_network_nodes.json")

    print(f"[ML] Anomaly Monitor started (PyG + Optuna) – collecting from '{hostname}'")

    while True:
        try:
            time.sleep(POLL_INTERVAL)

            # Check if we need to reset the network GNN
            global _reset_gnn_flag
            with _reset_gnn_flag_lock:
                if _reset_gnn_flag:
                    print("[ML] Resetting Network GNN state (user requested)")
                    net_detector = PyGNetworkAnomalyDetector()
                    net_buffer.clear()
                    network_graph = {"nodes": [], "edges": []}
                    _set_ml_state({"network_graph": network_graph})
                    if os.path.exists(_MODEL_SAVE_PATH):
                        try:
                            os.remove(_MODEL_SAVE_PATH)
                        except OSError:
                            pass
                    _reset_gnn_flag = False

            # ---- 1. Collect local telemetry ----------------------------
            current_local_processes = {p.info['name'] for p in psutil.process_iter(['name']) if p.info.get('name')}
            new_local_processes = current_local_processes - local_known_processes
            
            cpu = round(psutil.cpu_percent(interval=0.3), 1)
            ram = round(psutil.virtual_memory().percent, 1)
            usb = 0  # placeholder; USB count is expensive to query

            if hostname not in buffers:
                buffers[hostname] = deque(maxlen=ROLLING_WINDOW)
                detectors[hostname] = AnomalyDetector(contamination=0.05)

            new_processes_detected = []
            if len(buffers[hostname]) >= MIN_TRAINING_POINTS and new_local_processes and local_known_processes:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                for proc_name in sorted(new_local_processes):
                    print(f"[ML] ⚠ NEW PROCESS FLAGGED: '{proc_name}' on {hostname} at {now_str}")
                new_entry = {
                    "timestamp": now_str,
                    "hostname": hostname,
                    "new_processes": sorted(list(new_local_processes))
                }
                new_processes_detected.append(new_entry)
                
                try:
                    if os.path.exists(new_processes_log_file):
                        with open(new_processes_log_file, 'r', encoding='utf-8') as f:
                            np_log = json.load(f)
                        if not isinstance(np_log, list): np_log = []
                    else:
                        np_log = []
                    np_log.append(new_entry)
                    with open(new_processes_log_file, 'w', encoding='utf-8') as f:
                        json.dump(np_log, f, indent=2)
                except Exception as exc:
                    print(f"[ML] Failed to persist new processes: {exc}")

            local_known_processes.update(current_local_processes)
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
            
            # ---- 3.5 Network Graph + GNN Anomaly Detection ---------------
            try:
                live_conns = get_live_connections()
                net_buffer.append(live_conns)
                
                # Always build the graph from live connections so the
                # visualisation works immediately, even before GNN trains.
                nodes_set = set()
                edges = []
                
                NET_TRAINING_THRESHOLD = 5  # ~25 seconds
                
                if len(net_buffer) >= NET_TRAINING_THRESHOLD and live_conns:
                    net_detector.train_baseline(list(net_buffer))
                    scored_conns = net_detector.score_connections(live_conns)
                else:
                    # Pre-training: show all connections as normal
                    scored_conns = [
                        dict(c, anomaly_score=0.0, is_anomaly=False)
                        for c in live_conns
                    ]
                
                # Deduplicate edges: keep worst score per (local, remote) pair
                edge_map = {}  # (from_ip, to_ip) → edge dict
                for c in scored_conns:
                    key = (c["local_ip"], c["remote_ip"])
                    nodes_set.add(c["local_ip"])
                    nodes_set.add(c["remote_ip"])
                    existing = edge_map.get(key)
                    if existing is None or c.get("anomaly_score", 0) > existing.get("score", 0):
                        edge_map[key] = {
                            "from": c["local_ip"],
                            "to": c["remote_ip"],
                            "is_anomaly": c.get("is_anomaly", False),
                            "score": c.get("anomaly_score", 0.0),
                            "process": c.get("process_name", "Unknown")
                        }
                
                edges = list(edge_map.values())
                nodes = [{"id": n, "label": n} for n in nodes_set]
                network_graph = {
                    "nodes": nodes,
                    "edges": edges,
                    "gnn_info": net_detector.get_gnn_info(),
                }
                
                # Check for new network nodes
                new_nodes = nodes_set - known_network_nodes
                if known_network_nodes and new_nodes:
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    new_nodes_log_entries = []
                    for node in new_nodes:
                        print(f"[ML] ⚠ NEW NETWORK NODE DETECTED: {node}")
                        
                        anomaly_entry = {
                            "timestamp": now_str,
                            "hostname": hostname,
                            "type": "new_node",
                            "node_ip": node,
                            "score": 1.0,
                            "top_processes": []
                        }
                        anomalies_detected.append(anomaly_entry)
                        _append_to_history(anomaly_entry)
                        
                        new_nodes_log_entries.append({
                            "timestamp": now_str,
                            "hostname": hostname,
                            "node_ip": node
                        })
                        
                    # Persist to new_network_nodes.json
                    try:
                        if os.path.exists(new_network_nodes_log_file):
                            with open(new_network_nodes_log_file, 'r', encoding='utf-8') as f:
                                nn_log = json.load(f)
                            if not isinstance(nn_log, list): nn_log = []
                        else:
                            nn_log = []
                        nn_log.extend(new_nodes_log_entries)
                        with open(new_network_nodes_log_file, 'w', encoding='utf-8') as f:
                            json.dump(nn_log, f, indent=2)
                    except Exception as exc:
                        print(f"[ML] Failed to persist new network nodes: {exc}")

                known_network_nodes.update(nodes_set)
                
                for c in scored_conns:
                    if c.get("is_anomaly"):
                        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        print(f"[ML] ⚠ NEW NETWORK ANOMALY: {c['local_ip']} <-> {c['remote_ip']} (Score: {c['anomaly_score']:.2f})")
                        anomaly_entry = {
                            "timestamp": now_str,
                            "hostname": hostname,
                            "type": "network",
                            "connection": c,
                            "score": c["anomaly_score"],
                            "top_processes": []
                        }
                        anomalies_detected.append(anomaly_entry)
                        _append_to_history(anomaly_entry)
            except Exception as net_exc:
                import traceback
                print(f"[ML] Network GNN error: {net_exc}")
                traceback.print_exc()

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
                "new_processes": new_processes_detected,
                "network_graph": network_graph,
            })

            if anomalies_detected:
                with open(anomalies_file, 'w') as f:
                    json.dump(anomalies_detected, f)

        except Exception as e:
            print(f"[ML] Error in anomaly monitor: {e}")
