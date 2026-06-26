"""
VirusTotal IP Reputation Checker — queries the VirusTotal API v3 for
public IPs observed in the network graph and flags malicious ones.

Runs as a background daemon thread. Rate-limited to respect VT's free-tier
quota (4 requests/minute).
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIR = _PACKAGE_ROOT / "mnt" / "master"
VT_RESULTS_FILE = str(_LOG_DIR / "virustotal_results.json")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

POLL_INTERVAL = 30          # seconds between scans for new IPs
VT_RATE_LIMIT = 15.0        # seconds between API calls (4/min = 15s each)

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

_state_lock = threading.Lock()
_state: dict = {
    "status": "Initialising",
    "api_key_set": False,
    "checked_count": 0,
    "malicious_count": 0,
    "last_check_time": "",
    "results": {},       # {ip: result_dict}
}

_results_lock = threading.Lock()
_results_cache: dict[str, dict] = {}   # ip -> VT result


def get_vt_state() -> dict:
    """Thread-safe getter for the current VT checker state."""
    with _state_lock:
        return json.loads(json.dumps(_state))


def get_vt_results() -> list[dict]:
    """Thread-safe getter for all VT results as a list."""
    with _results_lock:
        return list(_results_cache.values())


# ---------------------------------------------------------------------------
# IP filtering
# ---------------------------------------------------------------------------

def is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is a routable public address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# VirusTotal API
# ---------------------------------------------------------------------------

def check_ip(ip: str, api_key: str) -> dict | None:
    """Query VirusTotal API v3 for an IP address.

    Returns a simplified result dict or None on failure.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = Request(url, headers={"x-apikey": api_key})

    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 429:
            print(f"[VirusTotal] Rate limited — backing off")
            return None
        print(f"[VirusTotal] HTTP error for {ip}: {exc.code}")
        return None
    except (URLError, OSError) as exc:
        print(f"[VirusTotal] Network error for {ip}: {exc}")
        return None

    attrs = data.get("data", {}).get("attributes", {})
    last_analysis = attrs.get("last_analysis_stats", {})
    malicious = int(last_analysis.get("malicious", 0))
    suspicious = int(last_analysis.get("suspicious", 0))
    harmless = int(last_analysis.get("harmless", 0))
    undetected = int(last_analysis.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected

    # Determine verdict
    if malicious > 0:
        verdict = "Malicious"
    elif suspicious > 0:
        verdict = "Suspicious"
    elif total > 0:
        verdict = "Clean"
    else:
        verdict = "Unrated"

    return {
        "ip": ip,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "country": attrs.get("country", "Unknown"),
        "as_owner": attrs.get("as_owner", "Unknown"),
        "network": attrs.get("network", "Unknown"),
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _persist_results():
    """Write all cached results to disk."""
    try:
        os.makedirs(os.path.dirname(VT_RESULTS_FILE), exist_ok=True)
        with _results_lock:
            data = dict(_results_cache)
        with open(VT_RESULTS_FILE, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
    except Exception as exc:
        print(f"[VirusTotal] Failed to persist results: {exc}")


def _load_results_from_disk():
    """Seed cache from previous session."""
    if not os.path.exists(VT_RESULTS_FILE):
        return
    try:
        with open(VT_RESULTS_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            with _results_lock:
                _results_cache.update(data)
            print(f"[VirusTotal] Loaded {len(data)} cached results from disk")
    except Exception as exc:
        print(f"[VirusTotal] Could not load cached results: {exc}")


# ---------------------------------------------------------------------------
# Manual check (called by Flask route)
# ---------------------------------------------------------------------------

def manual_check_ip(ip: str) -> dict | None:
    """Manually check a single IP. Returns the result or None."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return None

    result = check_ip(ip, api_key)
    if result:
        with _results_lock:
            _results_cache[ip] = result
        _persist_results()
        _update_state_counts()
    return result


def _update_state_counts():
    """Recalculate state counters from cache."""
    with _results_lock:
        checked = len(_results_cache)
        mal = sum(1 for r in _results_cache.values() if r.get("verdict") == "Malicious")
    with _state_lock:
        _state["checked_count"] = checked
        _state["malicious_count"] = mal
        _state["results"] = {}  # Don't duplicate full results in state


# ---------------------------------------------------------------------------
# Background daemon
# ---------------------------------------------------------------------------

def run_virustotal_checker():
    """Background thread that checks new public IPs against VirusTotal.

    Reads IPs from the ML state's network_graph and checks uncached ones.
    """
    from cyber_monitor.ml_anomaly import get_ml_state, _append_to_history

    hostname = socket.gethostname()
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    _load_results_from_disk()

    if not api_key:
        print("[VirusTotal] No API key set (env VIRUSTOTAL_API_KEY). Checker will wait for key.")
        with _state_lock:
            _state["status"] = "Waiting for API key"
            _state["api_key_set"] = False
        # Keep polling in case the key is set later
        while not api_key:
            time.sleep(POLL_INTERVAL)
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()

    with _state_lock:
        _state["status"] = "Active"
        _state["api_key_set"] = True

    print("[VirusTotal] Checker started — scanning for new public IPs")

    while True:
        try:
            time.sleep(POLL_INTERVAL)

            # Refresh API key in case it was set/changed at runtime
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
            if not api_key:
                with _state_lock:
                    _state["status"] = "Waiting for API key"
                    _state["api_key_set"] = False
                continue

            with _state_lock:
                _state["api_key_set"] = True
                _state["status"] = "Active"

            # Collect public IPs from the network graph
            ml_state = get_ml_state()
            graph = ml_state.get("network_graph", {})
            nodes = graph.get("nodes", [])

            public_ips = set()
            for node in nodes:
                ip = node.get("id", "")
                if is_public_ip(ip):
                    public_ips.add(ip)

            # Find unchecked IPs
            with _results_lock:
                unchecked = [ip for ip in public_ips if ip not in _results_cache]

            if not unchecked:
                continue

            print(f"[VirusTotal] {len(unchecked)} new public IP(s) to check")

            for ip in unchecked:
                result = check_ip(ip, api_key)
                if result is None:
                    time.sleep(VT_RATE_LIMIT)
                    continue

                with _results_lock:
                    _results_cache[ip] = result

                _update_state_counts()

                with _state_lock:
                    _state["last_check_time"] = result["checked_at"]

                print(f"[VirusTotal] {ip} → {result['verdict']} "
                      f"({result['malicious']}/{result['total_engines']} engines, "
                      f"{result['as_owner']}, {result['country']})")

                # Flag malicious/suspicious IPs as anomalies
                if result["verdict"] in ("Malicious", "Suspicious"):
                    anomaly_entry = {
                        "timestamp": result["checked_at"],
                        "hostname": hostname,
                        "type": "virustotal",
                        "ip": ip,
                        "verdict": result["verdict"],
                        "malicious_count": result["malicious"],
                        "total_engines": result["total_engines"],
                        "as_owner": result["as_owner"],
                        "country": result["country"],
                        "score": 1.0,
                        "top_processes": [],
                    }
                    _append_to_history(anomaly_entry)
                    print(f"[VirusTotal] ⚠ THREAT DETECTED: {ip} flagged as {result['verdict']}!")

                _persist_results()

                # Rate limit — wait between requests
                time.sleep(VT_RATE_LIMIT)

        except Exception as exc:
            print(f"[VirusTotal] Error in checker loop: {exc}")
