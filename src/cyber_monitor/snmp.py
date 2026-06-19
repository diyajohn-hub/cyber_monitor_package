from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from random import randint
from typing import Any

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
HR_STORAGE_UNIT = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_DEVICE_DESCR = "1.3.6.1.2.1.25.3.2.1.3"
HR_STORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HR_SW_RUN_NAME = "1.3.6.1.2.1.25.4.2.1.2"
HR_SW_RUN_PATH = "1.3.6.1.2.1.25.4.2.1.4"
HR_SW_RUN_TYPE = "1.3.6.1.2.1.25.4.2.1.6"
HR_SW_RUN_STATUS = "1.3.6.1.2.1.25.4.2.1.7"
HR_SW_RUN_PERF_CPU = "1.3.6.1.2.1.25.5.1.1.1"
HR_SW_RUN_PERF_MEM = "1.3.6.1.2.1.25.5.1.1.2"

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
}


@dataclass(frozen=True)
class SnmpValue:
    oid: str
    value: Any
    tag: int


class SnmpError(RuntimeError):
    pass


def discover_hosts(cidr: str, community: str = "public", timeout: float = 0.35) -> list[dict[str, Any]]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 512:
        hosts = hosts[:512]

    arp_entries = arp_table()
    devices: dict[str, dict[str, Any]] = {
        ip: {
            "ip": ip,
            "name": reverse_dns_name(ip),
            "description": "Discovered on local network",
            "mac": mac,
            "snmp": False,
            "open_ports": [],
        }
        for ip, mac in arp_entries.items()
        if ip_in_network(ip, network) and is_unicast_ipv4(ip)
    }

    local_ip = primary_ip()
    if ip_in_network(local_ip, network):
        devices.setdefault(
            local_ip,
            {
                "ip": local_ip,
                "name": socket.gethostname(),
                "description": "This monitoring device",
                "mac": arp_entries.get(local_ip, "Local"),
                "snmp": False,
                "open_ports": [],
            },
        )

    snmp_targets = sorted(devices)
    found_snmp: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=128) as executor:
        futures = {executor.submit(_probe_host, ip, community, timeout): ip for ip in snmp_targets}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_snmp.append(result)

    for item in found_snmp:
        existing = devices.get(item["ip"], {})
        devices[item["ip"]] = {
            **existing,
            **item,
            "mac": arp_entries.get(item["ip"], existing.get("mac", "Unknown")),
            "snmp": True,
            "open_ports": existing.get("open_ports", []),
        }

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(scan_common_ports, ip, 0.12): ip for ip in devices}
        for future in as_completed(futures):
            ip = futures[future]
            devices[ip]["open_ports"] = future.result()

    return sorted(
        devices.values(),
        key=lambda item: tuple(int(part) for part in item["ip"].split("."))
    )

def read_metrics(ip_address: str, community: str = "public", timeout: float = 1.0) -> dict[str, Any]:
    sys_name = get(ip_address, SYS_NAME, community, timeout)
    sys_descr = get(ip_address, SYS_DESCR, community, timeout)
    cpu_values = [int(item.value) for item in walk(ip_address, HR_PROCESSOR_LOAD, community, timeout) if isinstance(item.value, int)]
    ram = _read_ram(ip_address, community, timeout)
    usb_devices = _read_usb_devices(ip_address, community, timeout)
    processes = _read_processes(ip_address, community, timeout)

    return {
        "ip": ip_address,
        "name": str(sys_name.value) if sys_name else ip_address,
        "description": str(sys_descr.value) if sys_descr else "SNMP agent responded",
        "cpu": round(sum(cpu_values) / len(cpu_values), 1) if cpu_values else None,
        "cpu_cores": cpu_values,
        "ram": ram,
        "usb": usb_devices,
        "mac": arp_table().get(ip_address, "Unknown"),
        "open_ports": scan_common_ports(ip_address),
        "processes": processes,
    }


def get(ip_address: str, oid: str, community: str = "public", timeout: float = 1.0) -> SnmpValue | None:
    try:
        return _request(ip_address, oid, community, 0xA0, timeout)
    except (OSError, SnmpError, TimeoutError):
        return None


def walk(ip_address: str, base_oid: str, community: str = "public", timeout: float = 1.0) -> list[SnmpValue]:
    values: list[SnmpValue] = []
    current_oid = base_oid

    for _ in range(256):
        try:
            response = _request(ip_address, current_oid, community, 0xA1, timeout)
        except (OSError, SnmpError, TimeoutError):
            break

        if response is None or not _oid_startswith(response.oid, base_oid):
            break
        values.append(response)
        current_oid = response.oid

    return values


def default_cidr() -> str:
    ip_address = primary_ip()
    parts = ip_address.split(".")
    if len(parts) != 4 or ip_address.startswith("127."):
        return "192.168.1.0/24"
    return ".".join(parts[:3] + ["0"]) + "/24"


def primary_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def arp_table() -> dict[str, str]:
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    entries: dict[str, str] = {}
    for line in result.stdout.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+", line)
        if match:
            entries[match.group(1)] = match.group(2).lower()
    return entries

def arp_discover_hosts() -> list[dict[str, Any]]:
    entries = arp_table()

    hosts = []

    for ip, mac in entries.items():
        if not is_unicast_ipv4(ip):
            continue

        hosts.append(
            {
                "ip": ip,
                "name": reverse_dns_name(ip),
                "description": "Discovered via ARP",
                "mac": mac,
                "snmp": False,
                "open_ports": [],
            }
        )

    return hosts

def warmup_arp_cache(cidr: str):
    network = ipaddress.ip_network(cidr, strict=False)
    ping_sweep([str(ip) for ip in network.hosts()])


def ping_sweep(hosts: list[str]) -> None:
    with ThreadPoolExecutor(max_workers=128) as executor:
        futures = [executor.submit(_ping_host, ip) for ip in hosts]

        for future in futures:
            try:
                future.result()
            except Exception:
                pass


def _ping_host(ip_address: str) -> bool:
    command = ["ping", "-n", "1", "-w", "250", ip_address]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False

    return result.returncode == 0


def reverse_dns_name(ip_address: str) -> str:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except Exception:
        return ip_address


def ip_in_network(ip_address: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(ip_address) in network
    except ValueError:
        return False


def is_unicast_ipv4(ip_address: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    return bool(
        address.version == 4
        and not address.is_multicast
        and not address.is_loopback
        and not address.is_unspecified
        and not str(address).endswith(".255")
    )


def scan_common_ports(ip_address: str, timeout: float = 0.25) -> list[dict[str, Any]]:
    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {
            executor.submit(_is_tcp_port_open, ip_address, port, timeout): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(
                    {
                        "port": port,
                        "service": COMMON_PORTS[port],
                        "risk": port_risk(port),
                    }
                )

    return sorted(open_ports, key=lambda item: item["port"])


def port_risk(port: int) -> str:
    if port in {21, 23, 135, 139, 445, 3389, 5900}:
        return "Review exposure"
    if port in {80, 8080, 8443, 443, 22, 161}:
        return "Expected if intentionally enabled"
    return "Informational"


def _is_tcp_port_open(ip_address: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip_address, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_host(ip_address: str, community: str, timeout: float) -> dict[str, str] | None:
    sys_descr = get(ip_address, SYS_DESCR, community, timeout)
    if not sys_descr:
        return None

    sys_name = get(ip_address, SYS_NAME, community, timeout)
    return {
    "ip": ip_address,
    "name": str(sys_name.value) if sys_name else ip_address,
    "description": str(sys_descr.value),
    "snmp": True,
}


def _read_ram(ip_address: str, community: str, timeout: float) -> dict[str, Any]:
    types = _indexed_values(walk(ip_address, HR_STORAGE_TYPE, community, timeout))
    descriptions = _indexed_values(walk(ip_address, HR_STORAGE_DESCR, community, timeout))
    units = _indexed_values(walk(ip_address, HR_STORAGE_UNIT, community, timeout))
    sizes = _indexed_values(walk(ip_address, HR_STORAGE_SIZE, community, timeout))
    used = _indexed_values(walk(ip_address, HR_STORAGE_USED, community, timeout))

    candidates = []
    for index, description in descriptions.items():
        storage_type = str(types.get(index, ""))
        description_text = str(description).lower()
        if storage_type == HR_STORAGE_RAM or "memory" in description_text or "ram" in description_text:
            size = int(sizes.get(index, 0) or 0)
            used_size = int(used.get(index, 0) or 0)
            unit = int(units.get(index, 1) or 1)
            if size > 0:
                candidates.append((description, size, used_size, unit))

    if not candidates:
        return {"percent": None, "used_mb": None, "total_mb": None, "description": "RAM not exposed by SNMP agent"}

    description, size, used_size, unit = max(candidates, key=lambda item: item[1])
    total_mb = round(size * unit / 1024 / 1024, 1)
    used_mb = round(used_size * unit / 1024 / 1024, 1)
    return {
        "percent": round((used_size / size) * 100, 1),
        "used_mb": used_mb,
        "total_mb": total_mb,
        "description": str(description),
    }


def _read_usb_devices(ip_address: str, community: str, timeout: float) -> list[str]:
    descriptions = [str(item.value) for item in walk(ip_address, HR_DEVICE_DESCR, community, timeout)]
    storage_descriptions = [str(item.value) for item in walk(ip_address, HR_STORAGE_DESCR, community, timeout)]
    candidates = descriptions + storage_descriptions
    matches = [
        item
        for item in candidates
        if any(token in item.lower() for token in ("usb", "removable", "external", "flash"))
    ]
    return sorted(set(matches)) or ["No USB/removable devices exposed by SNMP agent"]


def _read_processes(ip_address: str, community: str, timeout: float) -> list[dict[str, Any]]:
    names = _indexed_values(walk(ip_address, HR_SW_RUN_NAME, community, timeout))
    paths = _indexed_values(walk(ip_address, HR_SW_RUN_PATH, community, timeout))
    types = _indexed_values(walk(ip_address, HR_SW_RUN_TYPE, community, timeout))
    statuses = _indexed_values(walk(ip_address, HR_SW_RUN_STATUS, community, timeout))
    cpu_ticks = _indexed_values(walk(ip_address, HR_SW_RUN_PERF_CPU, community, timeout))
    memory_kb = _indexed_values(walk(ip_address, HR_SW_RUN_PERF_MEM, community, timeout))

    processes = []
    for index, name in names.items():
        memory_mb = round(int(memory_kb.get(index, 0) or 0) / 1024, 1)
        processes.append(
            {
                "pid": int(index) if str(index).isdigit() else index,
                "name": str(name) or "Unknown",
                "status": _sw_run_status(statuses.get(index)),
                "type": _sw_run_type(types.get(index)),
                "path": str(paths.get(index, "")),
                "cpu_ticks": int(cpu_ticks.get(index, 0) or 0),
                "memory_mb": memory_mb,
                "disk_mbps": None,
                "network_mbps": None,
            }
        )

    return sorted(processes, key=lambda item: item["memory_mb"], reverse=True)[:120]


def _sw_run_status(value: Any) -> str:
    return {
        1: "running",
        2: "runnable",
        3: "not runnable",
        4: "invalid",
    }.get(int(value or 0), "unknown")


def _sw_run_type(value: Any) -> str:
    return {
        1: "unknown",
        2: "operating system",
        3: "device driver",
        4: "application",
    }.get(int(value or 0), "unknown")


def _indexed_values(values: list[SnmpValue]) -> dict[str, Any]:
    return {item.oid.rsplit(".", 1)[-1]: item.value for item in values}


def _request(ip_address: str, oid: str, community: str, pdu_tag: int, timeout: float) -> SnmpValue:
    packet = _build_packet(oid, community, pdu_tag)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip_address, 161))
        data, _ = sock.recvfrom(65535)
    return _parse_response(data)


def _build_packet(oid: str, community: str, pdu_tag: int) -> bytes:
    varbind = _sequence(_oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(
        pdu_tag,
        _integer(randint(1, 2_000_000_000))
        + _integer(0)
        + _integer(0)
        + _sequence(varbind),
    )
    return _sequence(_integer(1) + _octet_string(community.encode("ascii", errors="ignore")) + pdu)


def _parse_response(data: bytes) -> SnmpValue:
    message_value, _ = _read_tlv(data, 0)
    parts = _read_children(message_value)
    if len(parts) < 3:
        raise SnmpError("Invalid SNMP response")

    pdu_tag, pdu_value = parts[2]
    if pdu_tag != 0xA2:
        raise SnmpError("Unexpected SNMP response PDU")

    pdu_parts = _read_children(pdu_value)
    if len(pdu_parts) < 4:
        raise SnmpError("Invalid SNMP PDU")

    error_status = _decode_integer(pdu_parts[1][1])
    if error_status:
        raise SnmpError(f"SNMP error status {error_status}")

    varbinds = _read_children(pdu_parts[3][1])
    if not varbinds:
        raise SnmpError("SNMP response has no varbinds")

    varbind_parts = _read_children(varbinds[0][1])
    if len(varbind_parts) < 2:
        raise SnmpError("Invalid SNMP varbind")

    oid = _decode_oid(varbind_parts[0][1])
    value_tag, raw_value = varbind_parts[1]
    return SnmpValue(oid=oid, value=_decode_value(value_tag, raw_value), tag=value_tag)


def _read_children(data: bytes) -> list[tuple[int, bytes]]:
    children = []
    offset = 0
    while offset < len(data):
        value, offset, tag = _read_tlv(data, offset, include_tag=True)
        children.append((tag, value))
    return children


def _read_tlv(data: bytes, offset: int, include_tag: bool = False):
    if offset >= len(data):
        raise SnmpError("Unexpected end of BER data")

    tag = data[offset]
    length, value_offset = _read_length(data, offset + 1)
    end = value_offset + length
    if end > len(data):
        raise SnmpError("BER length exceeds packet")

    if include_tag:
        return data[value_offset:end], end, tag
    return data[value_offset:end], end


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    if first < 0x80:
        return first, offset + 1

    width = first & 0x7F
    value = 0
    for byte in data[offset + 1 : offset + 1 + width]:
        value = (value << 8) | byte
    return value, offset + 1 + width


def _decode_value(tag: int, value: bytes) -> Any:
    if tag == 0x02:
        return _decode_integer(value)
    if tag in {0x41, 0x42, 0x43, 0x46}:
        return int.from_bytes(value, "big", signed=False)
    if tag == 0x04:
        return value.decode("utf-8", errors="replace").strip("\x00")
    if tag == 0x06:
        return _decode_oid(value)
    if tag in {0x05, 0x80, 0x81, 0x82}:
        return None
    return value.hex()


def _decode_integer(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=value[0] >= 0x80)


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""

    first = value[0]
    parts = [first // 40, first % 40]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(number)
            number = 0
    return ".".join(str(part) for part in parts)


def _sequence(value: bytes) -> bytes:
    return _tlv(0x30, value)


def _integer(value: int) -> bytes:
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _octet_string(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    encoded = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        encoded += _base128(part)
    return _tlv(0x06, encoded)


def _base128(value: int) -> bytes:
    stack = [value & 0x7F]
    value >>= 7
    while value:
        stack.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(stack))


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _oid_startswith(oid: str, base_oid: str) -> bool:
    return oid == base_oid or oid.startswith(base_oid + ".")
