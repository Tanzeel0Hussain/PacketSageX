from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path


class NmapImportError(RuntimeError):
    pass


def parse_nmap_xml(path: str | Path) -> dict[str, object]:
    source = Path(path).expanduser().resolve()
    if not source.exists():
        raise NmapImportError(f"Nmap XML file not found: {source}")
    try:
        root = ET.parse(source).getroot()
    except ET.ParseError as exc:
        raise NmapImportError(f"Invalid Nmap XML: {exc}") from exc

    hosts: list[dict[str, object]] = []
    for host in root.findall("host"):
        status_node = host.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        addresses = [node.get("addr", "") for node in host.findall("address") if node.get("addr")]
        primary = next((a for a in addresses if _is_ip(a)), addresses[0] if addresses else "unknown")
        hostname_node = host.find("hostnames/hostname")
        hostname = hostname_node.get("name", "") if hostname_node is not None else ""
        ports: list[dict[str, object]] = []
        for port in host.findall("ports/port"):
            state_node = port.find("state")
            service_node = port.find("service")
            ports.append({
                "protocol": port.get("protocol", ""),
                "port": int(port.get("portid", "0")),
                "state": state_node.get("state", "unknown") if state_node is not None else "unknown",
                "service": service_node.get("name", "") if service_node is not None else "",
                "product": service_node.get("product", "") if service_node is not None else "",
                "version": service_node.get("version", "") if service_node is not None else "",
            })
        hosts.append({"address": primary, "addresses": addresses, "hostname": hostname, "status": status, "ports": ports})

    return {
        "schema": "packetsagex.nmap.v1",
        "source": str(source),
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "hosts": hosts,
        "host_count": len(hosts),
        "open_port_count": sum(1 for host in hosts for port in host["ports"] if port["state"] == "open"),
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
