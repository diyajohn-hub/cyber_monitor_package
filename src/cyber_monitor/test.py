from __future__ import annotations

import subprocess
import json
import platform
import socket
import time
from datetime import datetime

import psutil

# Collector Server IP
TARGET_IP = "192.168.1.103"
TARGET_PORT = 5000

PROCESS_LIMIT = 20


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def format_bytes(value: int) -> float:
    return round(value / 1024**2, 2)

def get_usb_devices():
    devices = []

    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                "Get-PnpDevice -Class USB | Select-Object -ExpandProperty FriendlyName"
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        for line in result.stdout.splitlines():

            line = line.strip()

            if line:
                devices.append(line)

    except Exception as e:
        print("USB error:", e)

    return devices  

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


def get_system_snapshot():
    now = datetime.now()

    memory = psutil.virtual_memory()

    usb_devices = get_usb_devices()

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

        "usb_devices": usb_devices,
        "usb_count": len(usb_devices),
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