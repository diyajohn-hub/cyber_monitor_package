# Cyber Monitor

A robust, real-time Flask dashboard designed for local system telemetry, host system event tracking, and advanced network threat intelligence. Tailored specifically for modern cyber cell monitoring environments.

## Overview

Cyber Monitor provides a suite of advanced tools designed to monitor hosts and networks, featuring live Machine Learning anomaly detection, Graph Neural Network (GNN) topology modeling, Windows Registry monitoring, and VirusTotal integration.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+** (Ensure `python.exe` is added to PATH on Windows).
- **Windows OS** is recommended for full functionality (Registry monitoring, Windows Event Viewer integration, and OS Service tracking).

### Installation & Setup

1. **Clone the repository and install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables (Optional but recommended):**
   To enable VirusTotal IP Threat Intelligence, set your free API key:
   ```powershell
   $env:VIRUSTOTAL_API_KEY = "your_api_key_here"
   ```

3. **Start the Application:**
   Set the Python path and run the main module:
   ```powershell
   $env:PYTHONPATH = "src"
   python -m cyber_monitor.app
   ```
   
   *Alternatively, use the provided batch script:*
   ```powershell
   .\run_monitor.bat
   ```

4. **Access the Dashboard:**
   Open your browser and navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## ✨ Key Features

### 🛡️ ML Anomaly Detection & GNN Modeling
- **Isolation Forest Algorithm:** Unsupervised machine learning continuously monitors CPU, RAM, and USB activity for anomalous behavior, automatically adapting to shifting baselines.
- **PyTorch Geometric (PyG) GNN Topology:** A live Graph Neural Network autoencoder models your local network traffic. Anomalous connections (e.g., massive unexpected data transfers) instantly flash red on the interactive dashboard.
- **Persistent Evidence Logging:** When an anomaly is detected, the system snapshots the top CPU-consuming processes and logs the event to a persistent, append-only JSON file (`mnt/master/anomaly_history.json`).

### 📂 Windows Registry Monitor
- **Real-Time Tracking:** A background daemon watches high-value registry keys (e.g., `Run`, `RunOnce`, `Services`, `Winlogon`) typically targeted by malware for persistence.
- **Change Detection:** Instantly detects additions, deletions, and value modifications, throwing an alert and logging the exact key path and value change.

### 🌐 VirusTotal IP Intelligence
- **Automated Threat Scanning:** Automatically extracts public IPs from active network connections and queries them against the VirusTotal API v3.
- **Smart Rate-Limiting & Caching:** Respects VT's free tier limits (4 requests/minute) by queuing IPs and caching results to disk to prevent redundant lookups.
- **Manual Checks:** Enter any IP manually in the UI to instantly pull its threat verdict, AS owner, and country of origin.

### 🔌 Live System & Network Telemetry
- **Local Monitoring (`/`):** Live CPU, RAM, and USB/removable storage connections.
- **Network Discovery (`/network`):** Scans a local IPv4 CIDR range using parallel ping sweeps and ARP cache warming to identify devices, reverse-DNS names, and common open TCP ports.
- **Security View (`/security`):** A consolidated dashboard showing live local processes, OS services grouped by category, ML stats, the live GNN graph, the Registry monitor, and VT Intelligence.
- **Windows Logs (`/logs`):** Consolidates local and client Windows Event Viewer logs (Application, Security, Setup, System).

---

## 🏗️ Project Architecture

```text
cyber_monitor_package/
├── src/cyber_monitor/
│   ├── app.py                   # Main Flask server and API routes
│   ├── ml_anomaly.py            # ML Isolation Forest & PyG GNN models
│   ├── registry_monitor.py      # Windows Registry change detection daemon
│   ├── virustotal_checker.py    # VirusTotal IP reputation checking daemon
│   ├── network.py               # LAN discovery and connection scanning
│   ├── snmp.py                  # SNMP device querying
│   ├── server.py                # Telemetry collector server
│   └── templates/               # Dashboard HTML templates
├── mnt/master/                  # Persistent logs and ML checkpoints
├── run_monitor.bat              # Windows launcher script
├── app.spec                     # PyInstaller build specification
└── requirements.txt             # Python dependencies
```

## 🔌 API Endpoints Reference

The dashboard is powered by these live internal APIs:

- **Telemetry & Services:**
  - `/api/local` — Local CPU/RAM/USB telemetry.
  - `/api/os/services` — Live OS service status and categories.
- **Security & ML:**
  - `/api/security/anomalies` — Active anomalies in the current cycle.
  - `/api/security/anomaly-history` — Full persistent history of detected anomalies.
  - `/api/security/network_graph` — Live GNN topology graph data.
  - `/api/security/registry` — Current state of monitored registry keys.
  - `/api/security/virustotal` — Cached VirusTotal results.
- **Network & Logs:**
  - `/api/network/scan` — Discovers reachable devices in the IPv4 range.
  - `/api/system/logs` — Recent Windows Event Viewer logs.

## 📦 Building an Executable

To compile the application into a standalone Windows executable:
```powershell
pyinstaller app.spec
```
The output will be placed in the `dist/` directory. Generated build and cache folders are ignored by git.
