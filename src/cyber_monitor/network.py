from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psutil

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP",
    135: "MS RPC", 139: "NetBIOS", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 5900: "VNC", 8080: "HTTP alternate", 8443: "HTTPS alternate",
}


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def default_cidr() -> str:
    parts = primary_ip().split(".")
    return ".".join(parts[:3] + ["0"]) + "/24" if len(parts) == 4 and parts[0] != "127" else "192.168.1.0/24"


def get_default_gateway() -> str | None:
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"], capture_output=True, check=False, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in result.stdout.splitlines():
            # Example line: "          0.0.0.0          0.0.0.0     10.103.4.116      10.103.4.95     55"
            line = line.strip()
            if line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def discover_devices(cidr: str) -> list[dict[str, Any]]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 network ranges are supported")
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 512:
        raise ValueError("Network range is too large; use /23 or a smaller range")

    reachable: set[str] = set()
    with ThreadPoolExecutor(max_workers=min(128, max(1, len(hosts)))) as executor:
        futures = {executor.submit(_ping, ip): ip for ip in hosts}
        for future in as_completed(futures):
            if future.result():
                reachable.add(futures[future])

    arp = arp_table()
    reachable.update(ip for ip in arp if ipaddress.ip_address(ip) in network)
    local_ip = primary_ip()
    if ipaddress.ip_address(local_ip) in network:
        reachable.add(local_ip)

    devices = {ip: {
        "ip": ip,
        "name": socket.gethostname() if ip == local_ip else reverse_dns_name(ip),
        "description": "This monitoring device" if ip == local_ip else "Device discovered on the local network",
        "mac": arp.get(ip, "Local" if ip == local_ip else "Unknown"),
        "open_ports": [],
    } for ip in reachable}

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(scan_common_ports, ip): ip for ip in devices}
        for future in as_completed(futures):
            devices[futures[future]]["open_ports"] = future.result()
    return sorted(devices.values(), key=lambda item: ipaddress.ip_address(item["ip"]))


def arp_table() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, check=False, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    entries = {}
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})", line)
        if match:
            entries[match.group(1)] = match.group(2).lower()
    return entries


def _ping(ip: str) -> bool:
    command = ["ping", "-n" if os.name == "nt" else "-c", "1"]
    command += (["-w", "300"] if os.name == "nt" else ["-W", "1"])
    try:
        result = subprocess.run(
            command + [ip], capture_output=True, check=False, timeout=2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def reverse_dns_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip


def scan_common_ports(ip: str, timeout: float = 0.18) -> list[dict[str, Any]]:
    found = []
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = {executor.submit(_port_open, ip, port, timeout): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                found.append({"port": port, "service": COMMON_PORTS[port]})
    return sorted(found, key=lambda item: item["port"])


def _port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_live_connections() -> list[dict[str, Any]]:
    """Retrieve active network connections and resolve process names."""
    connections = []
    # Fetch all connections
    try:
        net_conns = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        return []

    for conn in net_conns:
        if conn.status == 'ESTABLISHED' and conn.raddr:
            laddr_ip = conn.laddr.ip if conn.laddr else 'Unknown'
            raddr_ip = conn.raddr.ip if conn.raddr else 'Unknown'
            raddr_port = conn.raddr.port if conn.raddr else 0
            
            # Optionally resolve pid to process name
            proc_name = "Unknown"
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            connections.append({
                "local_ip": laddr_ip,
                "remote_ip": raddr_ip,
                "remote_port": raddr_port,
                "status": conn.status,
                "pid": conn.pid,
                "process_name": proc_name
            })
            
    return connections
