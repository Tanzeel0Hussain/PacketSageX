from __future__ import annotations

from collections import Counter
import csv
from pathlib import Path
from typing import Any, Iterable
import html

from .models import PacketRecord


PACKET_SAMPLE_LIMIT = 2500


def _port_label(packet: PacketRecord) -> str:
    src = f"{packet.src}:{packet.src_port}" if packet.src_port is not None else packet.src
    dst = f"{packet.dst}:{packet.dst_port}" if packet.dst_port is not None else packet.dst
    return f"{src or '?'} -> {dst or '?'}"


def describe_packet(packet: PacketRecord) -> str:
    """Return a short evidence-based description for a packet."""
    if packet.dns_query:
        if packet.dns_is_response:
            result = f"DNS response for {packet.dns_query}"
            if packet.dns_rcode:
                result += f" (rcode {packet.dns_rcode})"
            return result
        return f"DNS query for {packet.dns_query}"
    if packet.http_host:
        uri = packet.http_uri or "/"
        return f"HTTP request to {packet.http_host}{uri}"
    if packet.server_name:
        version = f" ({packet.tls_version})" if packet.tls_version else ""
        return f"TLS handshake/SNI {packet.server_name}{version}"
    if packet.quic_version:
        return f"QUIC traffic version {packet.quic_version}"
    if packet.protocol == "TCP":
        flags = f" flags={packet.tcp_flags}" if packet.tcp_flags else ""
        return f"TCP {_port_label(packet)}{flags}"
    if packet.protocol == "UDP":
        return f"UDP {_port_label(packet)}"
    return f"{packet.protocol} traffic {_port_label(packet)}"


def build_packet_analysis(packets: list[PacketRecord], sample_limit: int = PACKET_SAMPLE_LIMIT) -> dict[str, Any]:
    """Build packet-level statistics suitable for Wireshark capture review."""
    if not packets:
        return {
            "duration_seconds": 0.0,
            "average_packet_bytes": 0.0,
            "packets_per_second": 0.0,
            "protocol_counts": {},
            "tcp_flags": {},
            "top_source_ports": [],
            "top_destination_ports": [],
            "dns_packets": 0,
            "http_packets": 0,
            "tls_metadata_packets": 0,
            "quic_metadata_packets": 0,
            "sample_limit": sample_limit,
            "sampled_packets": 0,
            "truncated": False,
            "samples": [],
        }

    first_seen = min(packet.timestamp for packet in packets)
    last_seen = max(packet.timestamp for packet in packets)
    duration = max(0.0, last_seen - first_seen)
    protocol_counts = Counter(packet.protocol for packet in packets)
    tcp_flags = Counter(packet.tcp_flags for packet in packets if packet.tcp_flags)
    src_ports = Counter(packet.src_port for packet in packets if packet.src_port is not None)
    dst_ports = Counter(packet.dst_port for packet in packets if packet.dst_port is not None)

    samples = []
    for packet in packets[:sample_limit]:
        samples.append(
            {
                "number": packet.number,
                "time_offset": round(max(0.0, packet.timestamp - first_seen), 6),
                "length": packet.length,
                "src": packet.src,
                "dst": packet.dst,
                "protocol": packet.protocol,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "dns_query": packet.dns_query,
                "server_name": packet.server_name,
                "http_host": packet.http_host,
                "tcp_flags": packet.tcp_flags,
                "summary": describe_packet(packet),
            }
        )

    total_bytes = sum(packet.length for packet in packets)
    return {
        "duration_seconds": round(duration, 6),
        "average_packet_bytes": round(total_bytes / len(packets), 2),
        "packets_per_second": round(len(packets) / duration, 2) if duration > 0 else float(len(packets)),
        "protocol_counts": dict(protocol_counts.most_common()),
        "tcp_flags": dict(tcp_flags.most_common()),
        "top_source_ports": [{"port": port, "packets": count} for port, count in src_ports.most_common(15)],
        "top_destination_ports": [{"port": port, "packets": count} for port, count in dst_ports.most_common(15)],
        "dns_packets": sum(1 for packet in packets if packet.dns_query),
        "http_packets": sum(1 for packet in packets if packet.http_host),
        "tls_metadata_packets": sum(1 for packet in packets if packet.server_name or packet.tls_version),
        "quic_metadata_packets": sum(1 for packet in packets if packet.quic_version or "QUIC" in packet.protocol),
        "sample_limit": sample_limit,
        "sampled_packets": len(samples),
        "truncated": len(packets) > sample_limit,
        "samples": samples,
    }


def write_packets_csv(report: dict[str, Any], path: str | Path) -> Path:
    """Write packet-level rows captured in packet_analysis."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "number", "time_offset", "src", "src_port", "dst", "dst_port", "protocol",
        "length", "dns_query", "server_name", "http_host", "tcp_flags", "summary",
    ]
    samples = (report.get("packet_analysis", {}) or {}).get("samples", []) or []
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for sample in samples:
            writer.writerow({field: sample.get(field, "") for field in fields})
    return target


def _cell(value: object) -> str:
    return f"<td>{html.escape(str(value if value is not None else ''))}</td>"


def attach_packet_explorer(html_path: str | Path, report: dict[str, Any]) -> Path:
    """Add a searchable packet-level tab to an existing standalone HTML report."""
    target = Path(html_path)
    text = target.read_text(encoding="utf-8")
    if 'data-tab="packets"' in text:
        return target

    analysis = report.get("packet_analysis", {}) or {}
    samples = analysis.get("samples", []) or []
    protocols = analysis.get("protocol_counts", {}) or {}

    packet_rows = "".join(
        "<tr>" + "".join([
            _cell(item.get("number", "")),
            _cell(item.get("time_offset", "")),
            _cell(item.get("src", "")),
            _cell(item.get("dst", "")),
            _cell(item.get("protocol", "")),
            _cell(item.get("length", "")),
            _cell(item.get("summary", "")),
        ]) + "</tr>"
        for item in samples
    ) or '<tr><td colspan="7" class="empty">No packet samples available.</td></tr>'

    protocol_rows = "".join(
        "<tr>" + _cell(name) + _cell(count) + "</tr>"
        for name, count in protocols.items()
    ) or '<tr><td colspan="2" class="empty">No protocol data.</td></tr>'

    truncation = "Packet table is limited to the first {:,} packets for report performance.".format(
        int(analysis.get("sample_limit", PACKET_SAMPLE_LIMIT) or PACKET_SAMPLE_LIMIT)
    ) if analysis.get("truncated") else "All analyzed packets are represented in the packet table."

    section = f'''
  <section id="packets" class="tab-panel">
    <div class="section-title"><div><h2>Packet Explorer</h2><p>Packet-level review of the Wireshark capture.</p></div></div>
    <div class="grid">
      <div class="card"><div class="label">Duration</div><div class="metric">{float(analysis.get('duration_seconds', 0) or 0):,.2f}s</div></div>
      <div class="card"><div class="label">Avg Packet Size</div><div class="metric">{float(analysis.get('average_packet_bytes', 0) or 0):,.0f} B</div></div>
      <div class="card"><div class="label">Packet Rate</div><div class="metric">{float(analysis.get('packets_per_second', 0) or 0):,.1f}/s</div></div>
      <div class="card"><div class="label">Displayed Packets</div><div class="metric">{int(analysis.get('sampled_packets', 0) or 0):,}</div></div>
      <div class="card"><div class="label">DNS Packets</div><div class="metric">{int(analysis.get('dns_packets', 0) or 0):,}</div></div>
    </div>
    <div class="panel"><h3>Protocol Distribution</h3><div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Packets</th></tr></thead><tbody>{protocol_rows}</tbody></table></div></div>
    <div class="panel">
      <div class="controls screen-only"><input id="packetSearch" type="search" placeholder="Search packet number, source, destination, protocol, size or packet summary"><span id="packetResultCount"></span></div>
      <p class="note">{html.escape(truncation)}</p>
      <div class="table-wrap"><table id="packetTable"><thead><tr><th>No.</th><th>Time +s</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Bytes</th><th>Packet Analysis</th></tr></thead><tbody>{packet_rows}</tbody></table></div>
    </div>
  </section>
'''

    text = text.replace(
        '<button class="tab-btn" type="button" data-tab="flows">Flows</button>',
        '<button class="tab-btn" type="button" data-tab="flows">Flows</button>\n    <button class="tab-btn" type="button" data-tab="packets">Packets</button>',
        1,
    )
    text = text.replace('  <div class="footer">', section + '\n  <div class="footer">', 1)

    script = r'''
<script>
(()=>{
  const table=document.getElementById('packetTable');
  const search=document.getElementById('packetSearch');
  const count=document.getElementById('packetResultCount');
  if(!table||!search||!count)return;
  const tbody=table.querySelector('tbody');
  const rows=Array.from(tbody.querySelectorAll('tr')).filter(row=>row.children.length===7);
  function renderPackets(){
    const q=search.value.trim().toLowerCase();
    const visible=rows.filter(row=>!q||row.textContent.toLowerCase().includes(q));
    tbody.replaceChildren(...visible);
    count.textContent=`${visible.length} of ${rows.length} packets`;
  }
  search.addEventListener('input',renderPackets);
  renderPackets();
})();
</script>
'''
    text = text.replace('</body>', script + '\n</body>', 1)
    target.write_text(text, encoding="utf-8")
    return target
