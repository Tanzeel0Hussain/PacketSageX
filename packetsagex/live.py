from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any

from .capture.scapy_backend import packet_to_record
from .intelligence import TrafficClassifier
from .models import FlowSummary, PacketRecord
from .reporting import write_csv, write_html, write_json
from .security import security_findings


@dataclass(slots=True)
class _LiveFlow:
    summary: FlowSummary
    samples: deque[PacketRecord] = field(default_factory=lambda: deque(maxlen=50))


class LiveMonitor:
    """In-memory statistics for PacketSageX live capture mode."""

    def __init__(self, recent_limit: int = 12) -> None:
        self.started = time.monotonic()
        self.started_at = datetime.now().astimezone()
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

    def to_report(self, *, interface: str, capture_path: Path) -> dict[str, Any]:
        """Build the normal PacketSageX report schema from the current live session."""
        flows = [item.summary for item in self.flows.values()]
        flows.sort(key=lambda item: item.bytes, reverse=True)
        categories = Counter(flow.classification for flow in flows)
        sampled_packets = [
            packet
            for live_flow in self.flows.values()
            for packet in live_flow.samples
        ]
        return {
            "schema": "packetsagex.report.v1",
            "source": str(capture_path),
            "backend": "live-scapy",
            "interface": interface,
            "started_at": self.started_at.isoformat(),
            "finished_at": datetime.now().astimezone().isoformat(),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "flow_count": len(flows),
            "protocols": dict(self.protocols.most_common()),
            "top_endpoints": [
                {"endpoint": name, "packets": count}
                for name, count in self.endpoints.most_common(20)
            ],
            "traffic_categories": dict(categories.most_common()),
            "flows": [flow.to_dict() for flow in flows],
            "security_findings": security_findings(sampled_packets, flows),
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


def _new_session_directory(root: str | Path) -> Path:
    root_path = Path(root).expanduser().resolve()
    root_path.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    candidate = root_path / stamp
    suffix = 2
    while candidate.exists():
        candidate = root_path / f"{stamp}_{suffix:02d}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


def _restore_session_ownership(path: Path) -> None:
    """Give sudo-created report files back to the invoking desktop user on Unix."""
    uid_text = os.environ.get("SUDO_UID")
    gid_text = os.environ.get("SUDO_GID")
    if not uid_text or not gid_text or not hasattr(os, "chown"):
        return
    try:
        uid, gid = int(uid_text), int(gid_text)
        if path.is_dir():
            for child in path.rglob("*"):
                os.chown(child, uid, gid)
        os.chown(path, uid, gid)
    except (OSError, ValueError):
        pass


def _open_report(path: Path) -> bool:
    """Best-effort open of the HTML report, including sessions started through sudo."""
    path = path.resolve()
    sudo_user = os.environ.get("SUDO_USER")
    display = os.environ.get("DISPLAY")
    wayland_display = os.environ.get("WAYLAND_DISPLAY")
    dbus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    xauthority = os.environ.get("XAUTHORITY")

    try:
        if os.name != "nt" and sudo_user and hasattr(os, "geteuid") and os.geteuid() == 0:
            env_parts = []
            if display:
                env_parts.append(f"DISPLAY={display}")
            if wayland_display:
                env_parts.append(f"WAYLAND_DISPLAY={wayland_display}")
            if dbus:
                env_parts.append(f"DBUS_SESSION_BUS_ADDRESS={dbus}")
            if xauthority:
                env_parts.append(f"XAUTHORITY={xauthority}")
            command = ["sudo", "-u", sudo_user, "env", *env_parts, "xdg-open", str(path)]
            subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True

        if os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
            return True

        opener = shutil.which("xdg-open") or shutil.which("open")
        if opener:
            subprocess.Popen([opener, str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    except OSError:
        return False
    return False


def run_live_capture(
    *,
    interface: str = "any",
    refresh: float = 1.0,
    view: str = "dashboard",
    bpf_filter: str | None = None,
    save: str | Path | None = None,
    reports_dir: str | Path = "reports",
    open_report: bool = True,
) -> int:
    """Capture until Ctrl+C, save a timestamped session report, and open it."""
    try:
        from scapy.all import PcapWriter, sniff
    except Exception as exc:  # pragma: no cover - environment-specific
        raise RuntimeError("Live capture requires Scapy. Install PacketSageX dependencies first.") from exc

    if refresh <= 0:
        raise RuntimeError("--refresh must be greater than 0")

    session_dir = _new_session_directory(reports_dir)
    output_path = Path(save).expanduser().resolve() if save else session_dir / "capture.pcap"
    if output_path.suffix.lower() != ".pcap":
        raise RuntimeError("Live capture currently writes classic PCAP; use a .pcap filename")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    monitor = LiveMonitor()
    last_render = 0.0
    writer = PcapWriter(str(output_path), append=False, sync=True)

    print(f"Session reports: {session_dir}")
    if view == "dashboard":
        print("\033[2J\033[H" + monitor.render_dashboard(interface, bpf_filter), end="", flush=True)
    else:
        print(f"PacketSageX live stream on {interface}. Press Ctrl+C to stop.\n")

    def on_packet(raw_packet: object) -> None:
        nonlocal last_render
        number = monitor.packet_count + 1
        record = packet_to_record(raw_packet, number)
        label, confidence = monitor.add_record(record)
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
        writer.close()

    if view == "dashboard":
        print("\033[2J\033[H", end="")
    print(monitor.render_final())

    report = monitor.to_report(interface=interface, capture_path=output_path)
    json_path = write_json(report, session_dir / "analysis.json")
    csv_path = write_csv(report, session_dir / "flows.csv")
    html_path = write_html(report, session_dir / "report.html")
    _restore_session_ownership(session_dir)
    if not output_path.is_relative_to(session_dir):
        _restore_session_ownership(output_path)

    print(f"Capture : {output_path}")
    print(f"JSON    : {json_path}")
    print(f"CSV     : {csv_path}")
    print(f"HTML    : {html_path}")

    if open_report:
        if _open_report(html_path):
            print("Report opened automatically in your default browser.")
        else:
            print(f"Could not auto-open the browser. Open this file manually: {html_path}")

    return 0
