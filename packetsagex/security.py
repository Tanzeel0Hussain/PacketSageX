from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

from .models import FlowSummary, PacketRecord


def security_findings(packets: Iterable[PacketRecord], flows: Iterable[FlowSummary]) -> list[dict[str, object]]:
    packet_list = list(packets)
    flow_list = list(flows)
    findings: list[dict[str, object]] = []

    cleartext = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
    seen_cleartext: set[tuple[str, int]] = set()
    for flow in flow_list:
        for port in (flow.src_port, flow.dst_port):
            if port in cleartext and (cleartext[port], port) not in seen_cleartext:
                seen_cleartext.add((cleartext[port], port))
                findings.append({
                    "severity": "medium",
                    "type": "cleartext-service",
                    "title": f"Potential cleartext {cleartext[port]} traffic",
                    "evidence": f"Observed service port {port} in capture metadata.",
                })

    targets: dict[str, set[int]] = defaultdict(set)
    for flow in flow_list:
        if flow.src and flow.dst_port:
            targets[flow.src].add(flow.dst_port)
    for source, ports in targets.items():
        if len(ports) >= 15:
            findings.append({
                "severity": "high" if len(ports) >= 40 else "medium",
                "type": "port-scan-pattern",
                "title": "Possible port scanning pattern",
                "evidence": f"{source} contacted {len(ports)} distinct destination ports.",
            })

    dns_by_src = Counter(packet.src for packet in packet_list if packet.dns_query and packet.src)
    for source, count in dns_by_src.items():
        if count >= 100:
            findings.append({
                "severity": "medium",
                "type": "dns-burst",
                "title": "High DNS query volume",
                "evidence": f"{source} generated {count} DNS query packets.",
            })

    syn_by_src = Counter()
    for packet in packet_list:
        flags = packet.tcp_flags.upper()
        if packet.src and ("SYN" in flags or flags in {"S", "0X0002"}) and "ACK" not in flags:
            syn_by_src[packet.src] += 1
    for source, count in syn_by_src.items():
        if count >= 50:
            findings.append({
                "severity": "medium",
                "type": "syn-burst",
                "title": "Elevated TCP SYN activity",
                "evidence": f"{source} sent at least {count} SYN packets without ACK flag.",
            })

    return findings
