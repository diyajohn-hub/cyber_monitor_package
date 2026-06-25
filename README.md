# Cyber Monitor

A small Flask dashboard for local system telemetry, host system events, and network device discovery.

## Project layout

```text
src/cyber_monitor/          Application package
src/cyber_monitor/app.py    Flask app and telemetry endpoints
src/cyber_monitor/network.py LAN discovery and common-port scanning
src/cyber_monitor/templates Local and network dashboard templates
run_monitor.bat             Windows launcher
app.spec                    PyInstaller build specification
requirements.txt            Python dependencies
```

## Run locally

Install Python first if `python --version` or `py --version` does not work in PowerShell.
On Windows, install it from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.

```powershell
pip install -r requirements.txt
$env:PYTHONPATH = "src"
python -m cyber_monitor.app
```

This starts both services in one command:

- Dashboard: http://127.0.0.1:8000
- Collector socket: `0.0.0.0:5000` by default, or the next free port if `5000` is already busy

Agent metrics sent to the collector are stored in `mnt/master/log.json` and per-host files under `mnt/hosts/`. The dashboard shows the latest collector entries and the active collector port on the home page.

You can also run:

```powershell
.\run_monitor.bat
```

## Pages

- `/` shows CPU usage, RAM usage, and USB/removable storage connections for this device.
- `/network` scans a local IPv4 CIDR range and lists devices found through ping and ARP, with reverse-DNS names and common open TCP ports.
- `/logs` separates local and client Windows Event Viewer logs, with Application, Security, Setup, System, and Forwarded Events shown for each source.
- `/security` shows live local processes, memory usage, and OS services.

## ML Anomaly Detection

Cyber Monitor includes an unsupervised Machine Learning engine that continuously monitors system telemetry (CPU, RAM, USB activity) for anomalous behavior.

### How It Works
- **Isolation Forest Algorithm**: The system uses `scikit-learn`'s Isolation Forest model, which is highly effective at identifying outliers in multi-dimensional telemetry data without requiring pre-labeled training data.
- **Continuous Baseline Training**: The detector operates on a rolling window (e.g., the last 200 readings per host). It requires a minimum number of data points (e.g., 20 readings, or ~100 seconds) before it becomes "Active".
- **Online-ish Learning**: Every cycle (every 5 seconds), the model retrains on the latest rolling window. This allows it to slowly adapt to sustained changes in system behavior (e.g., a heavy workload starting up).
- **Per-Host Models**: A separate Isolation Forest is maintained for the local host as well as each remote client pushing data to the collector. 

### Model Behavior and Logging
Because the model continuously retrains, a sudden spike (like a runaway process consuming high CPU) will initially be flagged as an **Anomaly**. However, if that high CPU usage persists, the model's baseline will shift, and it will eventually start treating the new state as **Normal**.

To ensure security teams don't lose evidence of these transient anomalies:
1. **Process Snapshotting**: The exact moment an anomaly triggers, the ML engine captures a snapshot of the top 10 CPU-consuming processes.
2. **Persistent Append-Only Log**: The anomaly record (timestamp, telemetry features, anomaly score, and process snapshot) is written to an append-only JSON file (`mnt/master/anomaly_history.json`).
3. **Anomaly History View**: The dashboard's Security View includes an "Anomaly History" tab that displays this permanent record. Since it is append-only, the evidence remains available even after the ML model adapts to the anomaly and classifies it as normal.

## Local live APIs

- `/api/local` returns local CPU, RAM, and USB telemetry.
- `/api/memory/live` returns current RAM/swap usage, process count, and the highest-memory processes.
- `/api/os/services` returns live OS service status, service categories, and running/stopped summary counts.
- `/api/security/local` combines OS, memory, service, and alert data for the Security View.
- `/api/network/scan` discovers reachable devices in a local IPv4 range.
- `/api/system/logs` returns recent events grouped by the five standard Windows Event Viewer logs.
- `/api/collector/windows-logs` reads the collector log file on demand and returns deduplicated Windows events received from each client system.

The network page warms the ARP cache with a parallel ping sweep, includes devices from the ARP table, and checks a small set of common TCP ports.

## Build executable

```powershell
pyinstaller app.spec
```

Generated `build/`, `dist/`, and cache folders are intentionally ignored and can be recreated.

## Upcoming Changes

1. New Process
2. Windows registry adding or deleting
3. Network new connection or using of the internet excessively
4. Register IP that is connected in the network and check them in VirusTotal
