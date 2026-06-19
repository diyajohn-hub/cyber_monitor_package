# Cyber Monitor

A small Flask dashboard for local system telemetry and SNMP-enabled network device metrics.

## Project layout

```text
src/cyber_monitor/          Application package
src/cyber_monitor/app.py    Flask app and telemetry endpoints
src/cyber_monitor/snmp.py   Lightweight SNMP v2c client and metric readers
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
- `/network` scans a CIDR range for SNMP v2c devices and polls the selected device for CPU, RAM, and USB/removable-device details exposed by its SNMP agent.
- `/security` shows two live Task Manager-style tabs: this device's processes/services and SNMP-enabled devices discovered on the same network.

## Local live APIs

- `/api/local` returns local CPU, RAM, and USB telemetry.
- `/api/memory/live` returns current RAM/swap usage, process count, and the highest-memory processes.
- `/api/os/services` returns live OS service status, service categories, and running/stopped summary counts.
- `/api/security/local` combines OS, memory, service, and alert data for the Security View.
- `/api/snmp/metrics` includes SNMP HOST-RESOURCES process rows when the selected device exposes them.

The network page uses SNMP community `public` by default. The target device must have SNMP enabled and must expose HOST-RESOURCES-MIB data for CPU/RAM/USB details to appear.
The network page also enriches discovered SNMP devices with ARP MAC-address data and a common TCP port check for security review.

## Build executable

```powershell
pyinstaller app.spec
```

Generated `build/`, `dist/`, and cache folders are intentionally ignored and can be recreated.
