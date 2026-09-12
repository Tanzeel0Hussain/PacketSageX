from __future__ import annotations


def correlate_reports(capture: dict[str, object], nmap: dict[str, object]) -> dict[str, object]:
    endpoints = {item.get("endpoint") for item in capture.get("top_endpoints", []) if isinstance(item, dict)}
    matches: list[dict[str, object]] = []
    for host in nmap.get("hosts", []):
        if not isinstance(host, dict):
            continue
        address = host.get("address", "")
        if address in endpoints:
            matches.append({
                "address": address,
                "hostname": host.get("hostname", ""),
                "observed_in_capture": True,
                "open_ports": [
                    port for port in host.get("ports", [])
                    if isinstance(port, dict) and port.get("state") == "open"
                ],
            })
    return {
        "schema": "packetsagex.correlation.v1",
        "matched_hosts": matches,
        "matched_host_count": len(matches),
        "note": "Nmap data is imported only; PacketSageX does not scan targets during correlation.",
    }
