from __future__ import annotations

import json
import platform
import socket
import time
from datetime import datetime
import subprocess

import psutil

LAST_LOG_COLLECTION = 0
LOG_CACHE = {}
LOG_REFRESH_INTERVAL = 15   # seconds
WINDOWS_LOGS_PER_CHANNEL = 100

# Collector Server IP
ip = input("Enter your server addr (e.g., 1.15): ")

TARGET_IP = f"192.168.{ip}"
TARGET_PORT = 5000
PROCESS_LIMIT = 20


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    
def get_mac_address():
    try:
        interfaces = psutil.net_if_addrs()

        for iface_name, addresses in interfaces.items():
            for addr in addresses:

                # Windows MAC address
                if getattr(addr, "family", None) == psutil.AF_LINK:

                    mac = addr.address

                    if (
                        mac
                        and mac != "00:00:00:00:00:00"
                    ):
                        return mac

    except Exception:
        pass

    return "Unknown"

def get_usb_connected_count():
    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                "(Get-PnpDevice -Class USB | "
                "Where-Object {$_.Status -eq 'OK'}).Count"
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        count = result.stdout.strip()

        return int(count) if count.isdigit() else 0

    except Exception:
        return 0
    
def get_cached_windows_logs():
    global LAST_LOG_COLLECTION
    global LOG_CACHE

    current_time = time.time()

    if (
        not LOG_CACHE
        or current_time - LAST_LOG_COLLECTION >= LOG_REFRESH_INTERVAL
    ):
        print("Refreshing Windows Event Logs...")

        LOG_CACHE = get_windows_logs(WINDOWS_LOGS_PER_CHANNEL)
        LAST_LOG_COLLECTION = current_time

    return LOG_CACHE


def format_bytes(value: int) -> float:
    return round(value / 1024**2, 2)


def get_process_snapshot(limit: int = PROCESS_LIMIT):
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "status", "memory_percent"]
    ):
        try:
            info = process.info

            processes.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "user": info.get("username"),
                    "status": info.get("status"),
                    "memory_percent": round(
                        float(info.get("memory_percent") or 0), 2
                    ),
                }
            )

        except Exception:
            continue

    return processes[:limit]


EVENT_CHANNELS = [
    "Application",
    "Security",
    "Setup",
    "System",
    "ForwardedEvents",
]

def get_windows_logs(per_channel_limit=WINDOWS_LOGS_PER_CHANNEL):
    """Read the newest events from all major Windows event channels.

    Get-WinEvent is used because the legacy EventLog API can return incorrect
    data for modern channels such as Setup and ForwardedEvents.
    """
    windows_logs = {channel: [] for channel in EVENT_CHANNELS}

    if platform.system() != "Windows":
        return windows_logs

    channel_limit = max(1, int(per_channel_limit))

    for channel in EVENT_CHANNELS:
        try:
            escaped_channel = channel.replace("'", "''")
            script = (
                f"Get-WinEvent -LogName '{escaped_channel}' -MaxEvents {channel_limit} "
                "-ErrorAction Stop | "
                "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | "
                "ConvertTo-Json -Depth 4 -Compress"
            )
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                error = result.stderr.strip() or f"PowerShell exited with code {result.returncode}"
                windows_logs[channel] = [{"error": f"Unable to read {channel} channel: {error}"}]
                continue

            payload = json.loads(result.stdout) if result.stdout.strip() else []
            event_rows = payload if isinstance(payload, list) else [payload]
            windows_logs[channel] = [
                {
                    "event_id": event.get("Id"),
                    "source": str(event.get("ProviderName") or channel),
                    "timestamp": str(event.get("TimeCreated") or "Unknown"),
                    "level": str(event.get("LevelDisplayName") or "Information"),
                    "message": str(event.get("Message") or "").strip(),
                }
                for event in event_rows
                if isinstance(event, dict)
            ]
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            windows_logs[channel] = [{"error": f"Unable to read {channel} channel: {exc}"}]

    return windows_logs


def get_system_snapshot():
    now = datetime.now()

    memory = psutil.virtual_memory()

    return {
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "ip": primary_ip(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "cpu": {
            "percent": psutil.cpu_percent(interval=0.2),
            "cores": psutil.cpu_count(),
        },
        "memory": {
            "total_gb": round(memory.total / 1024**3, 2),
            "used_gb": round(memory.used / 1024**3, 2),
            "percent": memory.percent,
        },
        "process_count": len(psutil.pids()),
        "top_processes": get_process_snapshot(),
        "windows_logs": get_cached_windows_logs(),
        "mac_address": get_mac_address(),
        "usb_connected_count": get_usb_connected_count(),
    }


def start_agent():
    while True:
        try:
            print(f"Connecting to {TARGET_IP}:{TARGET_PORT}")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect((TARGET_IP, TARGET_PORT))

                print("Connected")

                while True:
                    metrics = get_system_snapshot()

                    payload = json.dumps(metrics) + "\n"

                    client.sendall(payload.encode("utf-8"))

                    print(
                        f"Sent | "
                        f"CPU={metrics['cpu']['percent']}% "
                        f"RAM={metrics['memory']['percent']}%"
                    )

                    time.sleep(1)

        except Exception as e:
            print("Connection failed:", e)
            print("Retrying in 5 seconds...")
            time.sleep(5)


if __name__ == "__main__":
    start_agent()
