from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
import shutil
import time
from typing import Any

from .capture.scapy_backend import packet_to_record
from .intelligence import TrafficClassifier
from .models import FlowSummary, PacketRecord


@dataclass(slots=True)
class _LiveFlow:
    summary: FlowSummary
    samples: deque[PacketRecord] = field(default_factory=lambda: deque(maxlen=50))


class LiveMonitor:
    """In-memory statistics for PacketSageX live capture mode."""

    def __init__(self, recent_limit: int = 12) -> None:
        self.started = time.monotonic()
        self.packet_count = 0
        self.byte_count = 0
        self.protocols: Counter[str] = Counter()
        self.endpoints: Counter[str] = Counter()
        self.flows: dict[str, _LiveFlow] = {}
        self.recent: deque[tuple[PacketRecord, str, int]] = deque(maxlen=recent_limit)
        self.classifier = TrafficClassifier()
        self._last_rate_time = self.started
        self._last_rate_packets = 0
        self._last_rate_bytes = 0
        self.current_pps = 0.0
        self.current_mbps = 0.0

    @staticmethod
    def _flow_key(packet: PacketRecord) -> str:
        left = (packet.src, packet.src_port or 0)
        right = (packet.dst, packet.dst_port or 0)
        ordered = sorted([left, right])
        return f"{ordered[0][0]}:{ordered[0][1]} <-> {ordered[1][0]}:{ordered[1][1]} / {packet.protocol}"

    def add_record(self, packet: PacketRecord) -> tuple[str, int]:
        self.packet_count += 1
        self.byte_count += packet.length
        self.protocols[packet.protocol] += 1
        if packet.src:
            self.endpoints[packet.src] += 1
        if packet.dst:
            self.endpoints[packet.dst] += 1

        key = self._flow_key(packet)
        live_flow = self.flows.get(key)
        if live_flow is None:
            summary = FlowSummary(
                key=key,
                src=packet.src,
                dst=packet.dst,
                protocol=packet.protocol,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                packets=0,
                bytes=0,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
            )
            live_flow = _LiveFlow(summary=summary)
            self.flows[key] = live_flow

        summary = live_flow.summary
        summary.packets += 1
        summary.bytes += packet.length
        summary.first_seen = min(summary.first_seen, packet.timestamp)
        summary.last_seen = max(summary.last_seen, packet.timestamp)
        live_flow.samples.append(packet)

        should_reclassify = (
            summary.packets <= 3
            or summary.packets % 10 == 0
            or bool(packet.dns_query or packet.server_name or packet.http_host)
        )
        if should_reclassify:
            summary.classification, summary.confidence, summary.evidence = self.classifier.classify(
                summary, live_flow.samples
            )

        self.recent.append((packet, summary.classification, summary.confidence))
        return summary.classification, summary.confidence

    def update_rates(self) -> None:
        now = time.monotonic()
        delta = max(0.001, now - self._last_rate_time)
        self.current_pps = (self.packet_count - self._last_rate_packets) / delta
        self.current_mbps = ((self.byte_count - self._last_rate_bytes) * 8) / delta / 1_000_000
        self._last_rate_time = now
        self._last_rate_packets = self.packet_count
        self._last_rate_bytes = self.byte_count

    def snapshot(self) -> dict[str, Any]:
        categories = Counter(flow.summary.classification for flow in self.flows.values())
        return {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "flow_count": len(self.flows),
            "protocols": dict(self.protocols.most_common()),
            "traffic_categories": dict(categories.most_common()),
            "top_endpoints": self.endpoints.most_common(10),
            "pps": self.current_pps,
            "mbps": self.current_mbps,
            "elapsed": max(0.0, time.monotonic() - self.started),
        }

    @staticmethod
    def _endpoint(packet: PacketRecord, source: bool) -> str:
        address = packet.src if source else packet.dst
        port = packet.src_port if source else packet.dst_port
        if not address:
            address = "?"
        return f"{address}:{port}" if port is not None else address

    def render_dashboard(self, interface: str, bpf_filter: str | None = None) -> str:
        self.update_rates()
        snap = self.snapshot()
        width = max(90, min(150, shutil.get_terminal_size((120, 40)).columns))
        line = "=" * width
        elapsed = float(snap["elapsed"])
        hours, rem = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(rem, 60)
        runtime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        out = [
            line,
            "PacketSageX LIVE — Network Traffic Intelligence",
            f"Interface: {interface}   Filter: {bpf_filter or 'none'}   Runtime: {runtime}   Stop: Ctrl+C",
            line,
            (
                f"Packets: {self.packet_count:,}   Flows: {len(self.flows):,}   "
                f"Bytes: {self.byte_count:,}   PPS: {self.current_pps:,.1f}   Speed: {self.current_mbps:,.3f} Mbps"
            ),
            "",
            "Top protocols:",
        ]
        protocols = self.protocols.most_common(8)
        out.append("  " + "   ".join(f"{name}: {count:,}" for name, count in protocols) if protocols else "  waiting for traffic...")

        categories = Counter(flow.summary.classification for flow in self.flows.values()).most_common(8)
        out.extend(["", "Traffic categories:"])
        if categories:
            for name, count in categories:
                out.append(f"  {count:>6,}  {name}")
        else:
            out.append("  waiting for traffic...")

        out.extend(["", "Top endpoints:"])
        if self.endpoints:
            out.append("  " + "   ".join(f"{name} ({count:,})" for name, count in self.endpoints.most_common(6)))
        else:
            out.append("  waiting for traffic...")

        out.extend(["", "Recent packets:"])
        if not self.recent:
            out.append("  waiting for packets...")
        else:
            for packet, label, confidence in list(self.recent)[-10:]:
                src = self._endpoint(packet, True)
                dst = self._endpoint(packet, False)
                row = (
                    f"  #{packet.number:<7} {packet.protocol:<8} {packet.length:>6} B  "
                    f"{src} -> {dst}  | {label} {confidence}%"
                )
                out.append(row[:width])

        out.extend([line, "Capture is running continuously. Press Ctrl+C when you want to stop."])
        return "\n".join(out)

    def render_final(self) -> str:
        elapsed = max(0.001, time.monotonic() - self.started)
        categories = Counter(flow.summary.classification for flow in self.flows.values()).most_common(10)
        out = [
            "\nPacketSageX live capture stopped.",
            f"Packets : {self.packet_count:,}",
            f"Flows   : {len(self.flows):,}",
            f"Bytes   : {self.byte_count:,}",
            f"Runtime : {elapsed:.1f}s",
            f"Average : {self.packet_count / elapsed:.1f} packets/s",
            "Traffic categories:",
        ]
        if categories:
            out.extend(f"  {count:>6,}  {name}" for name, count in categories)
        else:
            out.append("  none")
        return "\n".join(out)

    def format_stream_line(self, packet: PacketRecord, label: str, confidence: int) -> str:
        src = self._endpoint(packet, True)
        dst = self._endpoint(packet, False)
        return (
            f"#{packet.number:<7} {packet.protocol:<8} {packet.length:>6} B  "
            f"{src} -> {dst}  | {label} ({confidence}%)"
        )


def run_live_capture(
    *,
    interface: str = "any",
    refresh: float = 1.0,
    view: str = "dashboard",
    bpf_filter: str | None = None,
    save: str | Path | None = None,
) -> int:
    """Capture until Ctrl+C and display live PacketSageX intelligence."""
    try:
        from scapy.all import PcapWriter, sniff
    except Exception as exc:  # pragma: no cover - environment-specific
        raise RuntimeError("Live capture requires Scapy. Install PacketSageX dependencies first.") from exc

    if refresh <= 0:
        raise RuntimeError("--refresh must be greater than 0")

    monitor = LiveMonitor()
    last_render = 0.0
    writer = None
    output_path: Path | None = None
    if save:
        output_path = Path(save).expanduser().resolve()
        if output_path.suffix.lower() != ".pcap":
            raise RuntimeError("Live --save currently writes classic PCAP; use a .pcap filename")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        writer = PcapWriter(str(output_path), append=False, sync=True)

    if view == "dashboard":
        print("\033[2J\033[H" + monitor.render_dashboard(interface, bpf_filter), end="", flush=True)
    else:
        print(f"PacketSageX live stream on {interface}. Press Ctrl+C to stop.\n")

    def on_packet(raw_packet: object) -> None:
        nonlocal last_render
        number = monitor.packet_count + 1
        record = packet_to_record(raw_packet, number)
        label, confidence = monitor.add_record(record)
        if writer is not None:
            writer.write(raw_packet)

        now = time.monotonic()
        if view == "stream":
            print(monitor.format_stream_line(record, label, confidence), flush=True)
        elif now - last_render >= refresh:
            last_render = now
            print("\033[2J\033[H" + monitor.render_dashboard(interface, bpf_filter), end="", flush=True)

    try:
        sniff(
            iface=interface,
            prn=on_packet,
            store=False,
            filter=bpf_filter,
            promisc=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError as exc:
        raise RuntimeError(
            "Live capture permission denied. On Linux try: sudo .venv/bin/packetsagex live --interface any"
        ) from exc
    except OSError as exc:
        message = str(exc)
        if "permitted" in message.lower() or "permission" in message.lower():
            raise RuntimeError(
                "Live capture permission denied. On Linux try: sudo .venv/bin/packetsagex live --interface any"
            ) from exc
        raise RuntimeError(f"Live capture failed on interface {interface}: {exc}") from exc
    finally:
        if writer is not None:
            writer.close()

    if view == "dashboard":
        print("\033[2J\033[H", end="")
    print(monitor.render_final())
    if output_path is not None:
        print(f"Saved capture: {output_path}")
    return 0
