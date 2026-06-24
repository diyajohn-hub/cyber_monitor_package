"""
SERVER — Dual-port collector
Port 5000 → telemetry payloads  (CPU, RAM, processes, MAC, USB …)
Port 5001 → Windows Event Log payloads

Log layout
----------
mnt/
  master/
    log.json          ← all telemetry entries
    winlogs.json      ← all Windows-log entries (full + deltas)
  hosts/
    <hostname>.json   ← per-host telemetry
    <hostname>_winlogs.json  ← per-host Windows logs (merged, latest state)
"""

import json
import os
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HOST               = "0.0.0.0"
TELEMETRY_PORT     = int(os.environ.get("CYBER_TELEMETRY_PORT", "5000"))
WINLOG_PORT        = int(os.environ.get("CYBER_WINLOG_PORT",    "5001"))
PORT = TELEMETRY_PORT

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR      = Path(os.environ.get("CYBER_LOG_DIR", PACKAGE_ROOT / "mnt"))
MASTER_DIR   = LOG_DIR / "master"
HOST_DIR     = LOG_DIR / "hosts"

for d in (MASTER_DIR, HOST_DIR):
    d.mkdir(parents=True, exist_ok=True)

MASTER_TELEMETRY_LOG = MASTER_DIR / "log.json"
MASTER_WINLOG_LOG    = MASTER_DIR / "winlogs.json"
JSON_WRITE_LOCK      = threading.Lock()


# ---------------------------------------------------------------------------
# Generic JSON file helpers
# ---------------------------------------------------------------------------

def _read_json_list(path: Path) -> list:
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _write_json(path: Path, data) -> None:
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    with JSON_WRITE_LOCK:
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            for attempt in range(20):
                try:
                    os.replace(temp_path, path)
                    break
                except PermissionError:
                    if attempt == 19:
                        raise
                    time.sleep(0.05)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# Telemetry handlers
# ---------------------------------------------------------------------------

def write_telemetry(metrics: dict) -> None:
    """Append a telemetry snapshot to master log and per-host log."""
    hostname  = metrics.get("hostname", "unknown")
    entry     = {
        "received": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics":  metrics,
    }

    # Master log
    try:
        logs = _read_json_list(MASTER_TELEMETRY_LOG)
        logs.append(entry)
        _write_json(MASTER_TELEMETRY_LOG, logs)
    except Exception as exc:
        print(f"[Server] Master telemetry write error: {exc}")

    # Per-host log
    host_file = HOST_DIR / f"{hostname}.json"
    try:
        host_logs = _read_json_list(host_file)
        host_logs.append(entry)
        _write_json(host_file, host_logs)
    except Exception as exc:
        print(f"[Server] Host telemetry write error: {exc}")


def print_telemetry_summary(metrics: dict) -> None:
    hostname = metrics.get("hostname", "Unknown")
    ip       = metrics.get("ip", "Unknown")
    cpu      = metrics.get("cpu", {})
    memory   = metrics.get("memory", {})

    print("\n" + "=" * 80)
    print(f"[TELEMETRY]")
    print(f"  Host      : {hostname}")
    print(f"  IP        : {ip}")
    print(f"  Timestamp : {metrics.get('timestamp')}")
    print(f"  CPU       : {cpu.get('percent')}% ({cpu.get('cores')} cores)")
    print(f"  Memory    : {memory.get('percent')}%  Used {memory.get('used_gb')} GB")
    print(f"  Processes : {metrics.get('process_count')}")
    print(f"  MAC       : {metrics.get('mac_address')}")
    print(f"  USB count : {metrics.get('usb_connected_count')}")
    print("\n  Top Processes:")
    for proc in metrics.get("top_processes", [])[:5]:
        print(
            f"    PID={proc.get('pid')}  "
            f"Name={proc.get('name')}  "
            f"User={proc.get('user')}  "
            f"RAM={proc.get('memory_percent')}%"
        )
    print("=" * 80)


# ---------------------------------------------------------------------------
# Windows-log handlers
# ---------------------------------------------------------------------------

EVENT_CHANNELS = [
    "Application", "Security", "Setup", "System", "ForwardedEvents"
]


def _load_host_winlog_state(hostname: str) -> dict:
    """
    Returns the current merged state for a host:
    { channel: [ {event}, ... ], ... }
    """
    host_file = HOST_DIR / f"{hostname}_winlogs.json"
    if host_file.exists():
        try:
            with open(host_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except (json.JSONDecodeError, OSError):
            pass
    return {ch: [] for ch in EVENT_CHANNELS}


def _save_host_winlog_state(hostname: str, state: dict) -> None:
    host_file = HOST_DIR / f"{hostname}_winlogs.json"
    _write_json(host_file, state)


def write_winlogs(payload: dict) -> None:
    """
    Merge incoming Windows log payload into the per-host state file.
    Full payload  → replaces the stored events for each channel.
    Delta payload → appends new events to the stored events per channel.
    Also appends a timestamped entry to the master winlogs.json.
    """
    hostname = payload.get("hostname", "unknown")
    is_delta = payload.get("is_delta", False)
    logs     = payload.get("logs", {})
    received = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---- Update per-host merged state ----
    try:
        state = _load_host_winlog_state(hostname)

        for channel in EVENT_CHANNELS:
            incoming = logs.get(channel, [])
            if not incoming:
                continue

            # Skip error-only entries when merging
            real_events = [e for e in incoming if "error" not in e]

            if is_delta:
                # Append new events; de-duplicate by record_id
                existing_ids = {
                    e.get("record_id") for e in state.get(channel, [])
                    if isinstance(e.get("record_id"), int)
                }
                new_events = [
                    e for e in real_events
                    if e.get("record_id") not in existing_ids
                ]
                state.setdefault(channel, []).extend(new_events)
            else:
                # Full replace
                state[channel] = real_events

        _save_host_winlog_state(hostname, state)
    except Exception as exc:
        print(f"[Server] Host winlog state update error: {exc}")

    # ---- Append to master winlogs.json ----
    try:
        master_entry = {
            "received":  received,
            "hostname":  hostname,
            "is_delta":  is_delta,
            "timestamp": payload.get("timestamp"),
            "event_counts": {
                ch: len(logs.get(ch, [])) for ch in EVENT_CHANNELS
            },
        }
        master_logs = _read_json_list(MASTER_WINLOG_LOG)
        master_logs.append(master_entry)
        _write_json(MASTER_WINLOG_LOG, master_logs)
    except Exception as exc:
        print(f"[Server] Master winlog write error: {exc}")


def print_winlog_summary(payload: dict) -> None:
    hostname = payload.get("hostname", "Unknown")
    is_delta = payload.get("is_delta", False)
    logs     = payload.get("logs", {})
    mode     = "DELTA" if is_delta else "FULL"

    print("\n" + "=" * 80)
    print(f"[WIN LOGS — {mode}]  Host: {hostname}  @ {payload.get('timestamp')}")
    for channel in EVENT_CHANNELS:
        events = logs.get(channel, [])
        errors = [e for e in events if "error" in e]
        real   = [e for e in events if "error" not in e]
        line   = f"  {channel:<20}: {len(real):>6} events"
        if errors:
            line += f"  ⚠ {errors[0]['error']}"
        print(line)
    print("=" * 80)


# ---------------------------------------------------------------------------
# Generic client handler
# ---------------------------------------------------------------------------

def handle_client(conn: socket.socket, addr, port: int) -> None:
    label  = "TELEMETRY" if port == TELEMETRY_PORT else "WINLOG"
    print(f"[{label}] Connected: {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
            buffer += data.decode("utf-8", errors="replace")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(f"[{label}] JSON error from {addr}: {exc}")
                    continue

                ptype = payload.get("type", "")

                if ptype == "telemetry":
                    write_telemetry(payload)
                    print_telemetry_summary(payload)
                elif ptype == "winlogs":
                    write_winlogs(payload)
                    print_winlog_summary(payload)
                else:
                    # Legacy / unknown — treat as telemetry for backwards compat
                    write_telemetry(payload)
                    print_telemetry_summary(payload)

    except Exception as exc:
        print(f"[{label}] Client error {addr}: {exc}")
    finally:
        conn.close()
        print(f"[{label}] Disconnected: {addr}")


# ---------------------------------------------------------------------------
# Server threads
# ---------------------------------------------------------------------------

def _run_server(host: str, port: int) -> None:
    label = "TELEMETRY" if port == TELEMETRY_PORT else "WINLOG"
    srv   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(100)
    print(f"[{label}] Listening on {host}:{port}")

    while True:
        conn, addr = srv.accept()
        t = threading.Thread(
            target=handle_client, args=(conn, addr, port), daemon=True
        )
        t.start()


def start_server(host=None, port=None) -> None:
    if host is None:
      host = HOST

    if port is None:
      port = TELEMETRY_PORT

    print("=" * 80)
    print(f"Telemetry collector : port {TELEMETRY_PORT}")
    print(f"WinLog collector    : port {WINLOG_PORT}")
    print(f"Master telemetry log: {MASTER_TELEMETRY_LOG}")
    print(f"Master winlog log   : {MASTER_WINLOG_LOG}")
    print(f"Host logs dir       : {HOST_DIR}")
    print("=" * 80)

    t1 = threading.Thread(
        target=_run_server, args=(host, port), daemon=True
    )
    t2 = threading.Thread(
        target=_run_server, args=(HOST, WINLOG_PORT), daemon=True
    )
    t1.start()
    t2.start()

    # Keep main thread alive
    try:
        while True:
            t1.join(timeout=1)
            t2.join(timeout=1)
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")


if __name__ == "__main__":
    start_server()
