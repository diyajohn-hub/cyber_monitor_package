"""
Windows Registry Monitor — detects additions, deletions and value
modifications in security-critical registry keys.

Runs as a background daemon thread (same pattern as ``run_anomaly_monitor``).
Thread-safe getters expose the current state and change history to Flask.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Monitored registry keys — high-value targets for malware / persistence
# ---------------------------------------------------------------------------

MONITORED_KEYS: list[tuple[int, str]] = []

if sys.platform == "win32":
    import winreg

    MONITORED_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    ]

    _HIVE_NAMES = {
        winreg.HKEY_LOCAL_MACHINE: "HKLM",
        winreg.HKEY_CURRENT_USER: "HKCU",
    }

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIR = _PACKAGE_ROOT / "mnt" / "master"
REGISTRY_HISTORY_FILE = str(_LOG_DIR / "registry_changes.json")

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()
_state: dict = {
    "status": "Initialising",
    "monitored_keys": [],
    "recent_changes": [],
    "snapshot_time": "",
}

_history_lock = threading.Lock()
_history: list[dict] = []
_HISTORY_MAX = 500

POLL_INTERVAL = 10  # seconds


def get_registry_state() -> dict:
    """Thread-safe getter for the current registry monitor state."""
    with _state_lock:
        return json.loads(json.dumps(_state))


def get_registry_history(limit: int = 200) -> list[dict]:
    """Thread-safe getter for the registry change history."""
    with _history_lock:
        entries = list(_history)
    return list(reversed(entries[-limit:]))


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------

def _hive_name(hive: int) -> str:
    if sys.platform != "win32":
        return str(hive)
    return _HIVE_NAMES.get(hive, str(hive))


def _read_key_values(hive: int, subkey: str) -> dict[str, tuple[object, int]]:
    """Read all values under a single registry key.

    Returns {value_name: (data, type)} or empty dict on failure.
    """
    if sys.platform != "win32":
        return {}

    values: dict[str, tuple[object, int]] = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    name, data, vtype = winreg.EnumValue(key, idx)
                    values[name] = (data, vtype)
                    idx += 1
                except OSError:
                    break
    except OSError:
        pass
    return values


def _read_subkeys(hive: int, subkey: str) -> list[str]:
    """List immediate subkey names under a registry key."""
    if sys.platform != "win32":
        return []

    subkeys: list[str] = []
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            idx = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, idx))
                    idx += 1
                except OSError:
                    break
    except OSError:
        pass
    return subkeys


def take_snapshot() -> dict[str, dict[str, str]]:
    """Take a full snapshot of all monitored registry keys.

    Returns {full_key_path: {value_name: str(data), ...}}
    """
    snapshot: dict[str, dict[str, str]] = {}
    for hive, subkey in MONITORED_KEYS:
        full_path = f"{_hive_name(hive)}\\{subkey}"
        values = _read_key_values(hive, subkey)
        snapshot[full_path] = {name: str(data) for name, (data, _) in values.items()}

        # For Services key, also track subkey names (service registrations)
        if subkey.endswith("Services"):
            subkey_names = _read_subkeys(hive, subkey)
            for sk in subkey_names:
                snapshot[full_path][f"[Subkey] {sk}"] = "(service registered)"
    return snapshot


def diff_snapshots(
    old: dict[str, dict[str, str]],
    new: dict[str, dict[str, str]],
) -> list[dict]:
    """Compare two snapshots and return a list of change dicts."""
    changes: list[dict] = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_keys = set(old.keys()) | set(new.keys())
    for key_path in sorted(all_keys):
        old_vals = old.get(key_path, {})
        new_vals = new.get(key_path, {})

        # Additions
        for name in sorted(set(new_vals) - set(old_vals)):
            changes.append({
                "timestamp": now_str,
                "action": "ADDED",
                "key_path": key_path,
                "value_name": name,
                "old_value": None,
                "new_value": new_vals[name],
            })

        # Deletions
        for name in sorted(set(old_vals) - set(new_vals)):
            changes.append({
                "timestamp": now_str,
                "action": "DELETED",
                "key_path": key_path,
                "value_name": name,
                "old_value": old_vals[name],
                "new_value": None,
            })

        # Modifications
        for name in sorted(set(old_vals) & set(new_vals)):
            if old_vals[name] != new_vals[name]:
                changes.append({
                    "timestamp": now_str,
                    "action": "MODIFIED",
                    "key_path": key_path,
                    "value_name": name,
                    "old_value": old_vals[name],
                    "new_value": new_vals[name],
                })

    return changes


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _persist_changes(changes: list[dict]):
    """Append changes to the persistent JSON log."""
    try:
        os.makedirs(os.path.dirname(REGISTRY_HISTORY_FILE), exist_ok=True)
        if os.path.exists(REGISTRY_HISTORY_FILE):
            with open(REGISTRY_HISTORY_FILE, 'r', encoding='utf-8') as fh:
                history = json.load(fh)
            if not isinstance(history, list):
                history = []
        else:
            history = []
        history.extend(changes)
        with open(REGISTRY_HISTORY_FILE, 'w', encoding='utf-8') as fh:
            json.dump(history, fh, indent=2)
    except Exception as exc:
        print(f"[Registry] Failed to persist changes: {exc}")


def _load_history_from_disk():
    """Seed in-memory history from persistent file on startup."""
    if not os.path.exists(REGISTRY_HISTORY_FILE):
        return
    try:
        with open(REGISTRY_HISTORY_FILE, 'r', encoding='utf-8') as fh:
            history = json.load(fh)
        if isinstance(history, list):
            with _history_lock:
                for entry in history[-_HISTORY_MAX:]:
                    _history.append(entry)
            print(f"[Registry] Loaded {len(_history)} history entries from disk")
    except Exception as exc:
        print(f"[Registry] Could not load history: {exc}")


# ---------------------------------------------------------------------------
# Background daemon
# ---------------------------------------------------------------------------

def run_registry_monitor():
    """Background thread that monitors Windows Registry for changes.

    Pattern matches ``run_anomaly_monitor`` in ``ml_anomaly.py``.
    """
    # Lazy import to avoid circular dependency at module level
    from cyber_monitor.ml_anomaly import _append_to_history

    import socket
    hostname = socket.gethostname()

    if sys.platform != "win32":
        print("[Registry] Not running on Windows — registry monitor disabled.")
        with _state_lock:
            _state["status"] = "Disabled (non-Windows)"
        return

    _load_history_from_disk()

    print("[Registry] Taking initial baseline snapshot...")
    baseline = take_snapshot()
    monitored_paths = [f"{_hive_name(h)}\\{s}" for h, s in MONITORED_KEYS]

    with _state_lock:
        _state["status"] = "Active"
        _state["monitored_keys"] = monitored_paths
        _state["snapshot_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[Registry] Monitor started — watching {len(MONITORED_KEYS)} registry keys")

    while True:
        try:
            time.sleep(POLL_INTERVAL)

            current = take_snapshot()
            changes = diff_snapshots(baseline, current)

            if changes:
                print(f"[Registry] ⚠ {len(changes)} registry change(s) detected!")

                with _history_lock:
                    for ch in changes:
                        _history.append(ch)
                        # Trim if needed
                        if len(_history) > _HISTORY_MAX:
                            _history.pop(0)

                _persist_changes(changes)

                # Push to anomaly history
                for ch in changes:
                    anomaly_entry = {
                        "timestamp": ch["timestamp"],
                        "hostname": hostname,
                        "type": "registry",
                        "action": ch["action"],
                        "key_path": ch["key_path"],
                        "value_name": ch["value_name"],
                        "old_value": ch["old_value"],
                        "new_value": ch["new_value"],
                        "score": 1.0,
                        "top_processes": [],
                    }
                    _append_to_history(anomaly_entry)
                    print(f"[Registry] ⚠ {ch['action']}: {ch['key_path']} \\ {ch['value_name']}")

                with _state_lock:
                    _state["recent_changes"] = changes[-20:]
                    _state["snapshot_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Update baseline to current
                baseline = current
            else:
                with _state_lock:
                    _state["snapshot_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        except Exception as exc:
            print(f"[Registry] Error in monitor loop: {exc}")
