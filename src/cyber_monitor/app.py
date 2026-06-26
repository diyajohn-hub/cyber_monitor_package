from __future__ import annotations

import json
import platform
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

import psutil
from flask import Flask, jsonify, render_template, request, send_file

from cyber_monitor import server as collector_server
from cyber_monitor.network import default_cidr, discover_devices, primary_ip, get_default_gateway
from cyber_monitor.ml_anomaly import run_anomaly_monitor, get_ml_state, get_anomaly_history, reset_network_graph
import os

CPU_HISTORY = deque([0] * 10, maxlen=10)
LOCAL_RAM_HISTORY = deque([0] * 10, maxlen=10)
SERVICE_STATUS_HISTORY = deque([0] * 10, maxlen=10)
PROCESS_IO_HISTORY: dict[int, tuple[float, int]] = {}
COLLECTOR_THREAD: threading.Thread | None = None
ML_THREAD: threading.Thread | None = None


def template_dir() -> str:
    if getattr(sys, 'frozen', False):
        return str(Path(getattr(sys, '_MEIPASS')) / 'templates')
    return 'templates'


def create_app() -> Flask:
    app = Flask(__name__, template_folder=template_dir())

    global ML_THREAD
    if ML_THREAD is None:
        ML_THREAD = threading.Thread(target=run_anomaly_monitor, daemon=True)
        ML_THREAD.start()

    @app.after_request
    def disable_api_cache(response):
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    @app.get("/")
    def local_dashboard():
        return render_template("dashboard.html")

    @app.get("/network")
    def network_dashboard():
        return render_template("network.html", default_cidr=default_cidr())

    @app.get("/security")
    def security_dashboard():
        return render_template("security.html", default_cidr=default_cidr())

    @app.get("/logs")
    def system_logs_dashboard():
        return render_template("logs.html")

    @app.get("/api/local")
    def local_metrics():
        cpu_percent = round(psutil.cpu_percent(interval=0.2), 1)
        ram_percent = round(psutil.virtual_memory().percent, 1)

        CPU_HISTORY.append(cpu_percent)
        LOCAL_RAM_HISTORY.append(ram_percent)

        return jsonify(
            {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "hostname": socket.gethostname(),
                "ip": primary_ip(),
                "cpu": cpu_percent,
                "cpu_hist": list(CPU_HISTORY),
                "ram": ram_percent,
                "ram_hist": list(LOCAL_RAM_HISTORY),
                "usb": list_usb_devices(),
            }
        )

    @app.get("/api/security/anomalies")
    def security_anomalies():
        state = get_ml_state()
        return jsonify(state.get("anomalies", []))

    @app.get("/api/security/ml_stats")
    def security_ml_stats():
        return jsonify(get_ml_state())

    @app.get("/api/security/anomaly-history")
    def security_anomaly_history():
        try:
            limit = int(request.args.get("limit") or 200)
        except ValueError:
            limit = 200
        return jsonify(get_anomaly_history(max(1, min(limit, 500))))

    @app.get("/api/security/download-log")
    def download_security_log():
        from cyber_monitor.ml_anomaly import HISTORY_FILE
        if os.path.exists(HISTORY_FILE):
            return send_file(HISTORY_FILE, as_attachment=True, download_name="anomaly_history.json")
        return jsonify({"error": "Log file not found"}), 404

    @app.get("/api/security/network_graph")
    def security_network_graph():
        state = get_ml_state()
        return jsonify(state.get("network_graph", {"nodes": [], "edges": []}))

    @app.post("/api/security/network_graph/reset")
    def reset_security_network_graph():
        reset_network_graph()
        return jsonify({"status": "resetting"})

    @app.get("/api/collector/logs")
    def collector_logs():
        try:
            limit = int(request.args.get("limit") or 25)
        except ValueError:
            limit = 25

        return jsonify(read_collector_logs(max(1, min(limit, 200))))

    @app.get("/api/collector/status")
    def collector_status():
        return jsonify(
            {
                "host": collector_server.HOST,
                "port": collector_server.TELEMETRY_PORT,
                "master_log": str(collector_server.MASTER_TELEMETRY_LOG),
                "host_log_dir": str(collector_server.HOST_DIR),
                "running": bool(COLLECTOR_THREAD and COLLECTOR_THREAD.is_alive()),
            }
        )

    @app.get("/api/security/local")
    def local_security():
        return jsonify(local_security_snapshot())

    @app.get("/api/os/services")
    def os_services():
        return jsonify(live_service_snapshot())

    @app.get("/api/os/process-applications")
    def os_process_applications():
        try:
            pid = int(request.args.get("pid") or 0)
        except ValueError:
            pid = 0

        return jsonify({"pid": pid or None, "applications": process_applications(pid)})

    @app.get("/api/memory/live")
    def memory_live():
        return jsonify(live_memory_snapshot())

    @app.get("/api/network/scan")
    def scan_network():
        cidr = request.args.get("cidr") or default_cidr()
        try:
            targets = discover_devices(cidr)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        gateway_ip = get_default_gateway()
        return jsonify({"cidr": cidr, "targets": targets, "gateway_ip": gateway_ip})

    @app.get("/api/system/logs")
    def system_logs():
        limit_arg = str(request.args.get("limit") or "1000").strip().lower()
        if limit_arg == "all":
            limit: int | None = None
        else:
            try:
                limit = max(1, min(int(limit_arg), 5000))
            except ValueError:
                limit = 200
        return jsonify({"hostname": socket.gethostname(), "logs": read_windows_logs(limit)})

    @app.get("/api/collector/windows-logs")
    def collector_windows_logs():
        hostname = str(request.args.get("hostname") or "").strip()
        channel = str(request.args.get("channel") or "").strip()
        query = str(request.args.get("query") or "").strip()
        level = str(request.args.get("level") or "").strip()
        try:
            page = max(1, int(request.args.get("page") or 1))
            page_size = max(10, min(int(request.args.get("page_size") or 100), 500))
        except ValueError:
            page, page_size = 1, 100

        if hostname and channel:
            return jsonify(
                {
                    "detail": read_client_windows_log_channel(
                        hostname, channel, page, page_size, query, level
                    )
                }
            )
        return jsonify({"systems": read_client_windows_logs()})

    return app


def read_windows_logs(limit: int | None = None) -> list[dict[str, object]]:
    channel_names = ["Application", "Security", "Setup", "System", "ForwardedEvents"]
    if not sys.platform.startswith("win"):
        return [{"name": name, "events": [], "error": "Windows Event Logs are only available on Windows"}
                for name in channel_names]

    names = ",".join(f"'{name}'" for name in channel_names)
    event_command = "Get-WinEvent -LogName $name -ErrorAction Stop"
    if limit is not None:
        event_command = f"Get-WinEvent -LogName $name -MaxEvents {limit} -ErrorAction Stop"
    timeout = 120 if limit is None else 30
    script = (
        f"@({names}) | ForEach-Object {{ $name = $_; try {{ "
        f"$events = @({event_command} | "
        "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message); "
        "[PSCustomObject]@{Name=$name;Events=$events;Error=$null} "
        "} catch { [PSCustomObject]@{Name=$name;Events=@();Error=$_.Exception.Message} } "
        "} | ConvertTo-Json -Depth 5 -Compress"
    )
    timed_out = False
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script], capture_output=True,
            check=False, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        payload = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
    except subprocess.TimeoutExpired:
        payload = []
        timed_out = True
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        payload = []

    rows = payload if isinstance(payload, list) else [payload]
    rows_by_name = {str(row.get("Name")): row for row in rows if isinstance(row, dict)}
    logs = []
    for name in channel_names:
        row = rows_by_name.get(name, {})
        raw_events = row.get("Events") if isinstance(row.get("Events"), list) else []
        events = [{
            "timestamp": str(event.get("TimeCreated") or "Unknown"),
            "event_id": event.get("Id"),
            "level": event.get("LevelDisplayName") or "Information",
            "source": event.get("ProviderName") or name,
            "message": str(event.get("Message") or "No message").strip(),
        } for event in raw_events if isinstance(event, dict)]
        error = row.get("Error")
        if timed_out:
            error = "Reading all Windows log entries timed out; use a numeric limit for this large log set."
        logs.append({"name": name, "events": events if limit is None else events[:limit], "error": error})
    return logs


def read_client_windows_logs() -> list[dict[str, object]]:
    host_dir = Path(collector_server.HOST_DIR)
    latest_winlog_entries: dict[str, dict[str, object]] = {}
    for entry in load_log_file(Path(collector_server.MASTER_WINLOG_LOG)):
        hostname = str(entry.get("hostname") or "")
        if hostname:
            latest_winlog_entries[hostname] = entry

    systems = []
    for path in sorted(host_dir.glob("*_winlogs.json")):
        hostname = path.name.removesuffix("_winlogs.json")
        state = load_json_object(path)
        if not state:
            continue

        telemetry = latest_host_telemetry(host_dir / f"{hostname}.json")
        metrics = telemetry.get("metrics") if isinstance(telemetry.get("metrics"), dict) else {}
        latest_winlog = latest_winlog_entries.get(hostname, {})
        logs = []
        total_count = 0
        for channel_name in collector_server.EVENT_CHANNELS:
            raw_events = state.get(channel_name)
            events = raw_events if isinstance(raw_events, list) else []
            count = sum(1 for event in events if isinstance(event, dict) and not event.get("error"))
            error = next(
                (str(event["error"]) for event in events if isinstance(event, dict) and event.get("error")),
                None,
            )
            logs.append({"name": channel_name, "count": count, "events": [], "error": error})
            total_count += count

        systems.append(
            {
                "id": hostname,
                "hostname": hostname,
                "ip": str(metrics.get("ip") or "Unknown"),
                "received": latest_winlog.get("received")
                or datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "client_timestamp": latest_winlog.get("timestamp") or "Unknown",
                "total_count": total_count,
                "logs": logs,
            }
        )

    return sorted(systems, key=lambda item: str(item["hostname"]).lower())


def read_client_windows_log_channel(
    hostname: str,
    channel_name: str,
    page: int,
    page_size: int,
    query: str = "",
    level: str = "",
) -> dict[str, object]:
    safe_hostname = Path(hostname).name
    if safe_hostname != hostname or channel_name not in collector_server.EVENT_CHANNELS:
        return {"error": "Unknown client or Windows log channel.", "events": [], "count": 0}

    state = load_json_object(Path(collector_server.HOST_DIR) / f"{safe_hostname}_winlogs.json")
    raw_events = state.get(channel_name)
    events = []
    for event in raw_events if isinstance(raw_events, list) else []:
        if not isinstance(event, dict) or event.get("error"):
            continue
        normalized = {
            "record_id": event.get("record_id"),
            "timestamp": str(event.get("timestamp") or "Unknown"),
            "event_id": event.get("event_id"),
            "level": str(event.get("level") or "Information"),
            "source": str(event.get("source") or channel_name),
            "message": str(event.get("message") or "").strip(),
        }
        haystack = " ".join(str(value) for value in normalized.values()).lower()
        if query and query.lower() not in haystack:
            continue
        if level and normalized["level"].lower() != level.lower():
            continue
        events.append(normalized)

    events.sort(
        key=lambda event: (str(event.get("timestamp") or ""), int(event.get("record_id") or 0)),
        reverse=True,
    )
    count = len(events)
    page_count = max(1, (count + page_size - 1) // page_size)
    page = min(page, page_count)
    start = (page - 1) * page_size
    return {
        "hostname": safe_hostname,
        "channel": channel_name,
        "events": events[start:start + page_size],
        "count": count,
        "page": page,
        "page_size": page_size,
        "page_count": page_count,
        "query": query,
        "level": level,
    }


def load_json_object(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    for attempt in range(3):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            if attempt < 2:
                time.sleep(0.05)
    return {}


def latest_host_telemetry(path: Path) -> dict[str, object]:
    entries = load_log_file(path)
    return entries[-1] if entries else {}


def read_collector_logs(limit: int = 25) -> dict[str, object]:
    log_path = Path(collector_server.MASTER_TELEMETRY_LOG)
    host_logs_by_path = load_host_log_files(Path(collector_server.HOST_DIR))
    logs = flatten_host_logs(host_logs_by_path)

    if not logs:
        logs = load_log_file(log_path)
        if not logs:
            legacy_log = Path(__file__).resolve().parents[2] / "log.json"
            logs = load_log_file(legacy_log)
            log_path = legacy_log if logs else log_path

    recent_logs = logs[-limit:]
    hosts: dict[str, dict[str, object]] = {}
    system_logs: dict[str, list[dict[str, object]]] = {}

    if host_logs_by_path:
        for host_path, host_logs in host_logs_by_path.items():
            for entry in host_logs:
                add_system_log_entry(entry, host_path, hosts, system_logs)
    else:
        for entry in logs:
            add_system_log_entry(entry, log_path, hosts, system_logs)

    systems = []
    for system_key, host_logs in system_logs.items():
        host_logs = sorted(host_logs, key=log_sort_key)
        latest = host_logs[-1] if host_logs else {}
        systems.append(
            {
                "id": system_key,
                "hostname": latest.get("hostname") or system_key.split("|", 1)[0],
                "ip": latest.get("ip") or "Unknown",
                "source_path": latest.get("source_path") or "",
                "latest": latest,
                "count": len(host_logs),
                "logs": list(reversed(host_logs[-limit:])),
            }
        )

    return {
        "path": str(log_path),
        "host_log_dir": str(collector_server.HOST_DIR),
        "count": len(logs),
        "hosts": sorted(hosts.values(), key=lambda item: str(item["hostname"]).lower()),
        "systems": sorted(systems, key=lambda item: str(item["hostname"]).lower()),
        "logs": [format_collector_log(entry) for entry in reversed(recent_logs)],
    }


def load_host_log_files(host_dir: Path) -> dict[Path, list[dict[str, object]]]:
    if not host_dir.exists():
        return {}

    logs_by_path: dict[Path, list[dict[str, object]]] = {}
    for path in sorted(host_dir.glob("*.json")):
        logs = load_log_file(path)
        if logs:
            logs_by_path[path] = logs

    return logs_by_path


def flatten_host_logs(host_logs_by_path: dict[Path, list[dict[str, object]]]) -> list[dict[str, object]]:
    logs = [entry for host_logs in host_logs_by_path.values() for entry in host_logs]
    return sorted(logs, key=log_sort_key)


def log_sort_key(entry: dict[str, object]) -> str:
    metrics = entry.get("metrics") if isinstance(entry.get("metrics"), dict) else {}
    return str(entry.get("received") or metrics.get("timestamp") or "")


def add_system_log_entry(
    entry: dict[str, object],
    source_path: Path,
    hosts: dict[str, dict[str, object]],
    system_logs: dict[str, list[dict[str, object]]],
) -> None:
    if not isinstance(entry, dict):
        return

    metrics = entry.get("metrics") if isinstance(entry.get("metrics"), dict) else {}
    hostname = str(metrics.get("hostname") or source_path.stem or "unknown")
    ip_address = str(metrics.get("ip") or "Unknown")
    system_key = f"{hostname}|{ip_address}"
    cpu = metrics.get("cpu") if isinstance(metrics.get("cpu"), dict) else {}
    memory = metrics.get("memory") if isinstance(metrics.get("memory"), dict) else {}
    formatted_entry = format_collector_log(entry)
    formatted_entry["source_path"] = str(source_path)

    hosts[system_key] = {
        "hostname": hostname,
        "ip": ip_address,
        "received": entry.get("received") or metrics.get("timestamp") or "Unknown",
        "cpu": cpu.get("percent"),
        "memory": memory.get("percent"),
        "process_count": metrics.get("process_count"),
        "source_path": str(source_path),
    }
    system_logs.setdefault(system_key, []).append(formatted_entry)


def load_log_file(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []

    payload = None
    for attempt in range(3):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            break
        except (OSError, json.JSONDecodeError):
            if attempt < 2:
                time.sleep(0.05)

    if not isinstance(payload, list):
        return []

    return [entry for entry in payload if isinstance(entry, dict)]


def format_collector_log(entry: dict[str, object]) -> dict[str, object]:
    metrics = entry.get("metrics") if isinstance(entry.get("metrics"), dict) else {}
    cpu = metrics.get("cpu") if isinstance(metrics.get("cpu"), dict) else {}
    memory = metrics.get("memory") if isinstance(metrics.get("memory"), dict) else {}
    top_processes = metrics.get("top_processes") if isinstance(metrics.get("top_processes"), list) else []

    return {
        "received": entry.get("received") or "Unknown",
        "timestamp": metrics.get("timestamp") or "Unknown",
        "hostname": metrics.get("hostname") or "Unknown",
        "ip": metrics.get("ip") or "Unknown",
        "cpu": cpu.get("percent"),
        "cores": cpu.get("cores"),
        "memory": memory.get("percent"),
        "used_gb": memory.get("used_gb"),
        "process_count": metrics.get("process_count"),
        "top_processes": top_processes[:5],
    }


def start_collector_once() -> None:
    global COLLECTOR_THREAD

    if COLLECTOR_THREAD and COLLECTOR_THREAD.is_alive():
        return

    collector_port = available_collector_port(collector_server.HOST, collector_server.PORT)
    collector_server.PORT = collector_port
    COLLECTOR_THREAD = threading.Thread(
        target=collector_server.start_server,
        kwargs={"host": collector_server.HOST, "port": collector_port},
        name="collector-server",
        daemon=True,
    )
    COLLECTOR_THREAD.start()


def available_collector_port(host: str, preferred_port: int) -> int:
    for port in range(preferred_port, preferred_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host, port))
            except OSError:
                continue
        return port

    return preferred_port


def list_usb_devices() -> list[str]:
    devices = windows_usb_devices()

    for partition in psutil.disk_partitions(all=False):
        if "removable" in partition.opts.lower() or partition.device.upper().startswith(("E:", "F:", "G:", "H:")):
            devices.append(f"Removable storage: {partition.device} mounted at {partition.mountpoint}")

    return sorted(set(devices)) or ["No USB devices detected"]


def local_security_snapshot() -> dict[str, object]:
    memory_snapshot = live_memory_snapshot()
    service_snapshot = live_service_snapshot()
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    services = service_snapshot["services"]
    alerts = security_alerts(float(memory_snapshot["percent"]), services)

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "hostname": socket.gethostname(),
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "memory": memory_snapshot,
        "services": services,
        "service_summary": service_snapshot["summary"],
        "alerts": alerts,
    }


def live_memory_snapshot(limit: int = 80) -> dict[str, object]:
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    process_rows = []
    now = time.monotonic()

    for process in psutil.process_iter(["pid", "name", "username", "memory_percent", "memory_info", "status", "io_counters"]):
        try:
            info = process.info
            memory_info = info.get("memory_info")
            io_counters = info.get("io_counters")
            rss_mb = round((memory_info.rss if memory_info else 0) / 1024**2, 1)
            io_total = (io_counters.read_bytes + io_counters.write_bytes) if io_counters else 0
            previous = PROCESS_IO_HISTORY.get(int(info.get("pid") or 0))
            disk_mbps = 0.0
            if previous:
                elapsed = max(0.1, now - previous[0])
                disk_mbps = max(0.0, (io_total - previous[1]) / elapsed / 1024**2)
            PROCESS_IO_HISTORY[int(info.get("pid") or 0)] = (now, io_total)

            process_rows.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name") or "Unknown",
                    "user": info.get("username") or "Unknown",
                    "status": info.get("status") or "unknown",
                    "cpu_percent": round(float(process.cpu_percent(interval=None) or 0), 1),
                    "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                    "rss_mb": rss_mb,
                    "disk_mbps": round(disk_mbps, 2),
                    "network_mbps": 0,
                    "kind": process_kind(info.get("name") or ""),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    process_rows = sorted(
        process_rows,
        key=lambda item: item["memory_percent"],
        reverse=True,
    )[:limit]

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "percent": round(memory.percent, 1),
        "total_gb": round(memory.total / 1024**3, 2),
        "used_gb": round(memory.used / 1024**3, 2),
        "available_gb": round(memory.available / 1024**3, 2),
        "swap_percent": round(swap.percent, 1),
        "swap_used_gb": round(swap.used / 1024**3, 2),
        "process_count": len(psutil.pids()),
        "top_processes": process_rows[:15],
        "processes": process_rows,
    }


def live_service_snapshot() -> dict[str, object]:
    services = os_services_list(process_memory_by_pid())
    summary = service_summary(services)
    SERVICE_STATUS_HISTORY.append(summary["running"])

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "summary": summary,
        "running_history": list(SERVICE_STATUS_HISTORY),
        "services": services,
    }


def os_services_list(memory_by_pid: dict[int, dict[str, object]] | None = None) -> list[dict[str, object]]:
    if sys.platform.startswith("win"):
        return windows_services(memory_by_pid or {})
    return unix_services()


def windows_services(memory_by_pid: dict[int, dict[str, object]]) -> list[dict[str, object]]:
    services = []
    if not sys.platform.startswith("win"):
        return services

    cim_services = windows_services_from_cim(memory_by_pid)
    if cim_services:
        return cim_services

    try:
        iterator = psutil.win_service_iter()
    except AttributeError:
        return services

    for service in iterator:
        try:
            name = service.name()
            display_name = service.display_name()
            status = service.status()
            start_type = service.start_type()
            pid = service.pid()
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, OSError):
            continue

        name = str(name or "")
        display_name = str(display_name or "")
        services.append(
            {
                "name": name,
                "display_name": display_name,
                "status": status or "unknown",
                "start_type": start_type or "unknown",
                "pid": pid,
                "category": service_category(name, display_name),
                **memory_by_pid.get(int(pid or 0), service_process_memory(None)),
            }
        )

    return sorted(services, key=lambda item: (service_sort_rank(item), str(item["name"]).lower()))


def windows_services_from_cim(memory_by_pid: dict[int, dict[str, object]]) -> list[dict[str, object]]:
    script = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,ProcessId | "
        "ConvertTo-Json -Depth 3"
    )
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            timeout=12,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    rows = payload if isinstance(payload, list) else [payload]
    services = []
    for row in rows:
        if not isinstance(row, dict):
            continue

        name = str(row.get("Name") or "")
        display_name = str(row.get("DisplayName") or name)
        pid = int(row.get("ProcessId") or 0)
        services.append(
            {
                "name": name,
                "display_name": display_name,
                "status": str(row.get("State") or "unknown").lower(),
                "start_type": str(row.get("StartMode") or "unknown").lower(),
                "pid": pid or None,
                "category": service_category(name, display_name),
                **memory_by_pid.get(pid, service_process_memory(None)),
            }
        )

    return sorted(services, key=lambda item: (service_sort_rank(item), str(item["name"]).lower()))


def unix_services() -> list[dict[str, object]]:
    command = ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"]
    try:
        result = subprocess.run(command, capture_output=True, check=False, text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return []

    services = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(".service"):
            continue

        name = parts[0]
        display_name = parts[4] if len(parts) > 4 else name
        services.append(
            {
                "name": name,
                "display_name": display_name,
                "status": parts[3],
                "start_type": parts[2],
                "pid": None,
                "category": service_category(name, display_name),
                **service_process_memory(None),
            }
        )

    return sorted(services, key=lambda item: (service_sort_rank(item), str(item["name"]).lower()))


def service_summary(services: list[dict[str, object]]) -> dict[str, int]:
    summary = {"total": len(services), "running": 0, "stopped": 0, "security": 0, "review": 0, "memory_mb": 0}
    counted_memory_pids = set()
    for service in services:
        status = str(service.get("status") or "").lower()
        category = str(service.get("category") or "")
        pid = service.get("pid")
        if status == "running":
            summary["running"] += 1
        else:
            summary["stopped"] += 1
        if category == "security":
            summary["security"] += 1
        if service_sort_rank(service) == 0:
            summary["review"] += 1
        if pid and pid not in counted_memory_pids:
            summary["memory_mb"] += int(float(service.get("memory_mb") or 0))
            counted_memory_pids.add(pid)
    return summary


def service_process_memory(pid: int | None) -> dict[str, object]:
    if not pid:
        return {"memory_mb": 0.0, "memory_percent": 0.0, "process_name": ""}

    try:
        process = psutil.Process(int(pid))
        memory_info = process.memory_info()
        return {
            "memory_mb": round(memory_info.rss / 1024**2, 1),
            "memory_percent": round(process.memory_percent(), 2),
            "process_name": process.name(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        return {"memory_mb": 0.0, "memory_percent": 0.0, "process_name": ""}


def process_memory_by_pid() -> dict[int, dict[str, object]]:
    rows: dict[int, dict[str, object]] = {}
    for process in psutil.process_iter(["pid", "name", "memory_info", "memory_percent"]):
        try:
            info = process.info
            pid = int(info.get("pid") or 0)
            memory_info = info.get("memory_info")
            rows[pid] = {
                "memory_mb": round(((memory_info.rss if memory_info else 0) / 1024**2), 1),
                "memory_percent": round(float(info.get("memory_percent") or 0), 2),
                "process_name": info.get("name") or "",
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue
    return rows


def process_applications(pid: int | None) -> list[dict[str, object]]:
    if not pid:
        return []

    try:
        process = psutil.Process(int(pid))
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        return []

    applications = []
    try:
        process_info = process.as_dict(attrs=["pid", "name", "exe", "cmdline", "status", "username"])
        applications.append(process_application_row(process_info, "selected process"))
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        return applications

    try:
        children = process.children(recursive=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
        children = []

    for child in children[:12]:
        try:
            child_info = child.as_dict(attrs=["pid", "name", "exe", "cmdline", "status", "username"])
            applications.append(process_application_row(child_info, "child process"))
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, ValueError):
            continue

    return applications


def process_application_row(info: dict[str, object], relation: str) -> dict[str, object]:
    cmdline = info.get("cmdline") or []
    if isinstance(cmdline, list):
        command = " ".join(str(part) for part in cmdline)
    else:
        command = str(cmdline)

    return {
        "pid": info.get("pid"),
        "name": info.get("name") or "Unknown",
        "path": info.get("exe") or "",
        "command": command,
        "status": info.get("status") or "unknown",
        "user": info.get("username") or "",
        "relation": relation,
    }


def service_category(name: str, display_name: str) -> str:
    combined = f"{name} {display_name}".lower()
    categories = {
        "security": ("defender", "firewall", "security", "antivirus", "malware"),
        "remote": ("remote", "rdp", "ssh", "telnet", "vnc"),
        "network": ("rpc", "event", "wmi", "dns", "dhcp"),
        "update": ("update", "installer"),
    }
    for category, terms in categories.items():
        if any(term in combined for term in terms):
            return category
    return "system"


def service_sort_rank(service: dict[str, object]) -> int:
    status = str(service.get("status") or "").lower()
    category = str(service.get("category") or "")
    if category == "security" and status != "running":
        return 0
    if category in {"security", "remote", "network"}:
        return 1
    if status == "running":
        return 2
    return 3


def process_kind(name: str) -> str:
    app_names = (
        "chrome",
        "code",
        "codex",
        "edge",
        "explorer",
        "firefox",
        "notepad",
        "opera",
        "powershell",
        "snippingtool",
        "taskmgr",
        "terminal",
        "winword",
    )
    normalized = name.lower()
    if any(app_name in normalized for app_name in app_names):
        return "app"
    return "background"


def security_alerts(memory_percent: float, services: list[dict[str, object]]) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    if memory_percent >= 90:
        alerts.append({"level": "High", "message": "Memory usage is above 90%."})
    elif memory_percent >= 80:
        alerts.append({"level": "Medium", "message": "Memory usage is elevated."})

    stopped_security_services = [
        service["display_name"] or service["name"]
        for service in services
        if str(service["status"]).lower() != "running"
        and any(term in str(service["name"]).lower() + str(service["display_name"]).lower() for term in ("defender", "firewall", "security"))
    ]
    for service_name in stopped_security_services[:5]:
        alerts.append({"level": "Review", "message": f"Security-related service not running: {service_name}."})

    return alerts or [{"level": "OK", "message": "No immediate local memory or service alerts detected."}]


def windows_usb_devices() -> list[str]:
    if not sys.platform.startswith("win"):
        return []

    rows = run_usb_inventory_command(
        "Get-CimInstance Win32_PnPEntity | "
        "Where-Object { $_.PNPDeviceID -like 'USB\\*' -or $_.PNPDeviceID -like 'USBSTOR\\*' } | "
        "Select-Object @{Name='Name';Expression={$_.Name}},"
        "@{Name='DeviceClass';Expression={$_.PNPClass}},"
        "@{Name='Manufacturer';Expression={$_.Manufacturer}},"
        "@{Name='Status';Expression={$_.Status}},"
        "@{Name='DeviceId';Expression={$_.PNPDeviceID}} | "
        "ConvertTo-Json -Depth 3"
    )
    if not rows:
        rows = run_usb_inventory_command(
            "Get-PnpDevice -PresentOnly | "
            "Where-Object { $_.InstanceId -like 'USB\\*' -or $_.InstanceId -like 'USBSTOR\\*' } | "
            "Select-Object @{Name='Name';Expression={$_.FriendlyName}},"
            "@{Name='DeviceClass';Expression={$_.Class}},"
            "@{Name='Manufacturer';Expression={$_.Manufacturer}},"
            "@{Name='Status';Expression={$_.Status}},"
            "@{Name='DeviceId';Expression={$_.InstanceId}} | "
            "ConvertTo-Json -Depth 3"
        )

    devices: list[str] = []
    for row in rows:
        name = str(row.get("Name") or "").strip()
        if not name:
            continue

        device_class = str(row.get("DeviceClass") or "USB").strip()
        manufacturer = str(row.get("Manufacturer") or "").strip()
        status = str(row.get("Status") or "Unknown").strip()
        device_id = str(row.get("DeviceId") or "").strip()
        port_label = usb_port_label(device_id)
        label = f"{device_class}: {name}"
        if manufacturer and manufacturer.lower() not in name.lower():
            label = f"{label} ({manufacturer})"
        devices.append(f"{label} | {port_label} | {status}")

    return devices


def usb_port_label(device_id: str) -> str:
    if not device_id:
        return "Port: unknown"

    parts = [part for part in device_id.split("\\") if part]
    if len(parts) < 3:
        return f"Port path: {device_id}"

    instance_path = parts[-1]
    if instance_path.upper().startswith("ROOT_HUB"):
        return "USB root hub"

    port_number = instance_path.rsplit("&", 1)[-1]
    if port_number.isdigit():
        return f"USB port {port_number} ({device_id})"

    return f"USB path {instance_path} ({device_id})"


def run_usb_inventory_command(script: str) -> list[dict[str, object]]:
    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    rows = payload if isinstance(payload, list) else [payload]
    return [row for row in rows if isinstance(row, dict)]


app = create_app()


if __name__ == "__main__":
    start_collector_once()
    app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False)
