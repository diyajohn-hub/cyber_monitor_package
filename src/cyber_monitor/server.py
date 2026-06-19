import json
import os
import socket
import threading
from datetime import datetime
from pathlib import Path

HOST = "0.0.0.0"
PORT = int(os.environ.get("CYBER_COLLECTOR_PORT", "5000"))

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = Path(os.environ.get("CYBER_LOG_DIR", PACKAGE_ROOT / "mnt"))
MASTER_DIR = os.path.join(LOG_DIR, "master")
HOST_DIR = os.path.join(LOG_DIR, "hosts")

os.makedirs(MASTER_DIR, exist_ok=True)
os.makedirs(HOST_DIR, exist_ok=True)

MASTER_LOG = os.path.join(MASTER_DIR, "log.json")

def write_log(metrics):
    hostname = metrics.get("hostname", "unknown")
    log_entry = {
        "received": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": metrics
    }
    try:
        if os.path.exists(MASTER_LOG):
            with open(MASTER_LOG, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                    if not isinstance(logs, list): logs = []
                except json.JSONDecodeError: logs = []
        else: logs = []
        logs.append(log_entry)
        with open(MASTER_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"Master Log Write Error: {e}")

    host_log_file = os.path.join(HOST_DIR, f"{hostname}.json")
    try:
        if os.path.exists(host_log_file):
            with open(host_log_file, "r", encoding="utf-8") as f:
                try:
                    host_logs = json.load(f)
                    if not isinstance(host_logs, list): host_logs = []
                except json.JSONDecodeError: host_logs = []
        else: host_logs = []
        host_logs.append(log_entry)
        with open(host_log_file, "w", encoding="utf-8") as f:
            json.dump(host_logs, f, indent=2)
    except Exception as e:
        print(f"Host Log Write Error: {e}")


def print_summary(metrics):
    hostname = metrics.get("hostname", "Unknown")
    ip = metrics.get("ip", "Unknown")
    cpu = metrics.get("cpu", {})
    memory = metrics.get("memory", {})

    print("\n" + "=" * 80)
    print(f"Host       : {hostname}")
    print(f"IP         : {ip}")
    print(f"Timestamp  : {metrics.get('timestamp')}")
    print(f"CPU        : {cpu.get('percent')}% ({cpu.get('cores')} cores)")
    print(f"Memory     : {memory.get('percent')}% Used {memory.get('used_gb')} GB")
    print(f"Processes  : {metrics.get('process_count')}")
    
    # Safely iterates and processes your new multi-line custom device data array
    print("\nDetected USB Devices:")
    usb_list = metrics.get("usb_devices", ["No USB devices detected"])
    for dev in usb_list:
        print(f"  - {dev}")

    print("\nTop Processes")
    for proc in metrics.get("top_processes", [])[:5]:
        print(f"PID={proc.get('pid')} Name={proc.get('name')} User={proc.get('user')} RAM={proc.get('memory_percent')}%")
    print("=" * 80)


def handle_client(conn, addr):
    print(f"\n[+] Connected: {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(8192)
            if not data: break
            buffer += data.decode("utf-8")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip(): continue
                try:
                    metrics = json.loads(line)
                    write_log(metrics)
                    print_summary(metrics)
                except json.JSONDecodeError as e:
                    print(f"JSON Error: {e}")
    except Exception as e:
        print(f"Client Error {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected: {addr}")


def start_server(host=HOST, port=None):
    if port is None: port = PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)

    print("=" * 80)
    print(f"Collector Listening On {host}:{port}")
    print(f"Master Log : {MASTER_LOG}")
    print(f"Host Logs  : {HOST_DIR}")
    print("=" * 80)

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

if __name__ == "__main__":
    start_server()