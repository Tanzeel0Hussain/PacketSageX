from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from .capture import load_packets
from .intelligence import TrafficClassifier
from .models import FlowSummary, PacketRecord
from .security import security_findings


def _flow_key(packet: PacketRecord) -> str:
    left = (packet.src, packet.src_port or 0)
    right = (packet.dst, packet.dst_port or 0)
    ordered = sorted([left, right])
    return f"{ordered[0][0]}:{ordered[0][1]} <-> {ordered[1][0]}:{ordered[1][1]} / {packet.protocol}"


def analyze_capture(
    path: str | Path,
    *,
    backend: str = "auto",
    tls_keylog: str | Path | None = None,
    packet_limit: int | None = None,
) -> dict[str, object]:
    backend_name, packet_iter = load_packets(path, backend=backend, tls_keylog=tls_keylog)
    packets: list[PacketRecord] = []
    for packet in packet_iter:
        packets.append(packet)
        if packet_limit and len(packets) >= packet_limit:
            break

    grouped: dict[str, list[PacketRecord]] = defaultdict(list)
    for packet in packets:
        grouped[_flow_key(packet)].append(packet)

    classifier = TrafficClassifier()
    flows: list[FlowSummary] = []
    for key, members in grouped.items():
        first = members[0]
        summary = FlowSummary(
            key=key,
            src=first.src,
            dst=first.dst,
            protocol=first.protocol,
            src_port=first.src_port,
            dst_port=first.dst_port,
            packets=len(members),
            bytes=sum(item.length for item in members),
            first_seen=min(item.timestamp for item in members),
            last_seen=max(item.timestamp for item in members),
        )
        summary.classification, summary.confidence, summary.evidence = classifier.classify(summary, members)
        flows.append(summary)

    protocols = Counter(packet.protocol for packet in packets)
    endpoints = Counter()
    for packet in packets:
        if packet.src:
            endpoints[packet.src] += 1
        if packet.dst:
            endpoints[packet.dst] += 1

    classifications = Counter(flow.classification for flow in flows)
    total_bytes = sum(packet.length for packet in packets)
    report = {
        "schema": "packetsagex.report.v1",
        "source": str(Path(path)),
        "backend": backend_name,
        "packet_count": len(packets),
        "byte_count": total_bytes,
        "flow_count": len(flows),
        "protocols": dict(protocols.most_common()),
        "top_endpoints": [{"endpoint": name, "packets": count} for name, count in endpoints.most_common(20)],
        "traffic_categories": dict(classifications.most_common()),
        "flows": [flow.to_dict() for flow in sorted(flows, key=lambda item: item.bytes, reverse=True)],
    }
    report["security_findings"] = security_findings(packets, flows)
    return report
