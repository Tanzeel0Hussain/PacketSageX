from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import sys

from . import __version__
from .analysis import analyze_capture
from .banner import TAGLINE, render_banner
from .capture import CaptureError
from .correlate import correlate_reports
from .interfaces import resolve_live_interface, select_live_interface
from .live import _open_report, run_live_capture
from .nmap_import import NmapImportError, parse_nmap_xml
from .packet_analysis import attach_packet_explorer, write_packets_csv
from .pdf_report import attach_pdf_actions, write_pdf
from .reporting import write_csv, write_html, write_json

# Backward-compatible/internal test alias.
_select_live_interface = select_live_interface


def _print_banner() -> None:
    use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    print(render_banner(__version__, color=use_color))
    print()


def _summary(report: dict[str, object]) -> None:
    print(f"Backend : {report.get('backend', 'n/a')}")
    print(f"Packets : {report.get('packet_count', 0):,}")
    print(f"Flows   : {report.get('flow_count', 0):,}")
    print(f"Bytes   : {report.get('byte_count', 0):,}")
    print("\nTraffic categories:")
    for name, count in list((report.get("traffic_categories") or {}).items())[:10]:
        print(f"  {count:>6}  {name}")
    findings = report.get("security_findings") or []
    print(f"\nSecurity findings: {len(findings)}")
    for item in findings[:10]:
        print(f"  [{str(item.get('severity','info')).upper()}] {item.get('title')}")


def _packet_summary(report: dict[str, object]) -> None:
    info = report.get("packet_analysis") or {}
    if not isinstance(info, dict):
        return
    print("\nPacket intelligence:")
    print(f"Duration : {float(info.get('duration_seconds', 0) or 0):.2f}s")
    print(f"Avg size : {float(info.get('average_packet_bytes', 0) or 0):.1f} bytes")
    print(f"Rate     : {float(info.get('packets_per_second', 0) or 0):.1f} packets/s")
    print(
        "Metadata : "
        f"DNS {int(info.get('dns_packets', 0) or 0):,} | "
        f"HTTP {int(info.get('http_packets', 0) or 0):,} | "
        f"TLS {int(info.get('tls_metadata_packets', 0) or 0):,} | "
        f"QUIC {int(info.get('quic_metadata_packets', 0) or 0):,}"
    )
    protocols = info.get("protocol_counts") or {}
    if isinstance(protocols, dict) and protocols:
        print("Protocols:")
        for name, count in list(protocols.items())[:10]:
            print(f"  {int(count):>6,}  {name}")


def _new_analysis_directory(root: str | Path, prefix: str) -> Path:
    root_path = Path(root).expanduser().resolve()
    root_path.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    candidate = root_path / f"{prefix}_{stamp}"
    suffix = 2
    while candidate.exists():
        candidate = root_path / f"{prefix}_{stamp}_{suffix:02d}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="packetsagex", description=TAGLINE)
    parser.add_argument("--version", action="version", version=f"PacketSageX {__version__}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Analyze a PCAP/PCAPNG capture")
    analyze.add_argument("capture")
    analyze.add_argument("--backend", choices=["auto", "tshark", "scapy"], default="auto")
    analyze.add_argument("--tls-keylog", help="Authorized NSS/SSLKEYLOGFILE for decryptable TLS sessions")
    analyze.add_argument("--limit", type=int, help="Stop after N packets")
    analyze.add_argument("--json", dest="json_path")
    analyze.add_argument("--csv", dest="csv_path")
    analyze.add_argument("--packets-csv", dest="packets_csv_path")
    analyze.add_argument("--html", dest="html_path")
    analyze.add_argument(
        "--pdf",
        dest="pdf_path",
        help="Write a native paginated PDF report. When --html is used, a sibling PDF is created automatically.",
    )

    wireshark = sub.add_parser(
        "wireshark",
        help="Analyze a capture exported/saved by Wireshark and create packet-level reports",
    )
    wireshark.add_argument("capture", help="Wireshark .pcap, .pcapng, or .cap file")
    wireshark.add_argument("--backend", choices=["auto", "tshark", "scapy"], default="auto")
    wireshark.add_argument("--tls-keylog", help="Authorized NSS/SSLKEYLOGFILE for decryptable TLS sessions")
    wireshark.add_argument("--reports-dir", default="reports", help="Output root folder (default: reports)")
    wireshark.add_argument("--no-open", action="store_true", help="Do not open the generated HTML report")

    live = sub.add_parser("live", help="Monitor live traffic until Ctrl+C")
    live.add_argument(
        "-i",
        "--interface",
        default="any",
        help="Capture interface. 'any'/'auto' selects Scapy's active interface automatically.",
    )
    live.add_argument("--refresh", type=float, default=1.0, help="Dashboard refresh interval in seconds")
    live.add_argument("--view", choices=["dashboard", "stream"], default="dashboard")
    live.add_argument("--filter", dest="bpf_filter", help="Optional BPF capture filter, e.g. 'tcp or udp'")
    live.add_argument(
        "--save",
        help="Optional custom .pcap path. By default capture.pcap is stored in the timestamped report folder.",
    )
    live.add_argument(
        "--reports-dir",
        default="reports",
        help="Root folder for timestamped live-session reports (default: reports)",
    )
    live.add_argument(
        "--no-open",
        action="store_true",
        help="Do not automatically open the generated HTML report after Ctrl+C",
    )

    nmap = sub.add_parser("nmap", help="Import Nmap XML output")
    nmap.add_argument("xml")
    nmap.add_argument("--json", dest="json_path")

    correlate = sub.add_parser("correlate", help="Correlate an existing PacketSageX JSON report with Nmap XML")
    correlate.add_argument("report_json")
    correlate.add_argument("nmap_xml")
    correlate.add_argument("--json", dest="json_path")

    sub.add_parser("doctor", help="Check local runtime capabilities")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        _print_banner()
        parser.print_help()
        return 0

    if args.command == "doctor":
        _print_banner()
        print(f"Python  : {sys.version.split()[0]}")
        print(f"TShark  : {shutil.which('tshark') or 'not found'}")
        try:
            import scapy  # noqa: F401
            scapy_state = "available"
        except Exception:
            scapy_state = "not available"
        try:
            import reportlab  # noqa: F401
            pdf_state = "available"
        except Exception:
            pdf_state = "not available"
        print(f"Scapy   : {scapy_state}")
        print(f"PDF     : {pdf_state} (native professional report engine)")
        print("Live    : Scapy capture engine; runs until Ctrl+C")
        print("Wireshark: .pcap/.pcapng/.cap packet analysis supported")
        print("Reports : JSON/CSV/HTML/PDF + packet CSV")
        print("TLS keys: supported through TShark when you provide your own authorized key log")
        return 0

    try:
        if args.command == "analyze":
            _print_banner()
            report = analyze_capture(
                args.capture,
                backend=args.backend,
                tls_keylog=args.tls_keylog,
                packet_limit=args.limit,
            )
            _summary(report)
            _packet_summary(report)
            if args.json_path:
                print(f"JSON    : {write_json(report, args.json_path)}")
            if args.csv_path:
                print(f"CSV     : {write_csv(report, args.csv_path)}")
            if args.packets_csv_path:
                print(f"Packets : {write_packets_csv(report, args.packets_csv_path)}")

            pdf_target: Path | None = None
            if args.pdf_path:
                pdf_target = Path(args.pdf_path)
            elif args.html_path:
                pdf_target = Path(args.html_path).with_suffix(".pdf")

            written_pdf: Path | None = None
            if pdf_target is not None:
                written_pdf = write_pdf(report, pdf_target)
                print(f"PDF     : {written_pdf}")

            if args.html_path:
                html_path = write_html(report, args.html_path)
                attach_packet_explorer(html_path, report)
                if written_pdf is not None:
                    attach_pdf_actions(html_path, written_pdf)
                print(f"HTML    : {html_path}")
            return 0

        if args.command == "wireshark":
            _print_banner()
            capture_path = Path(args.capture).expanduser()
            if capture_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
                raise ValueError("Wireshark analysis expects a .pcap, .pcapng, or .cap file")
            if not capture_path.exists():
                raise ValueError(f"Capture file not found: {capture_path}")

            session = _new_analysis_directory(args.reports_dir, "wireshark")
            report = analyze_capture(capture_path, backend=args.backend, tls_keylog=args.tls_keylog)
            _summary(report)
            _packet_summary(report)

            json_path = write_json(report, session / "analysis.json")
            flows_path = write_csv(report, session / "flows.csv")
            packets_path = write_packets_csv(report, session / "packets.csv")
            pdf_path = write_pdf(report, session / "report.pdf")
            html_path = write_html(report, session / "report.html")
            attach_packet_explorer(html_path, report)
            attach_pdf_actions(html_path, pdf_path)

            print("\nWireshark capture analysis complete.")
            print(f"JSON    : {json_path}")
            print(f"Flows   : {flows_path}")
            print(f"Packets : {packets_path}")
            print(f"PDF     : {pdf_path}")
            print(f"HTML    : {html_path}")

            if not args.no_open:
                if _open_report(html_path):
                    print("Report opened automatically in your default browser.")
                else:
                    print(f"Open the report manually: {html_path}")
            return 0

        if args.command == "live":
            _print_banner()
            capture_interface = resolve_live_interface(args.interface)
            if capture_interface != args.interface:
                print(f"Interface: {args.interface} -> {capture_interface} (auto-selected by Scapy)")
            print("Starting continuous live capture. Press Ctrl+C whenever you want to stop.\n")

            reports_root = Path(args.reports_dir).expanduser().resolve()
            before = set(reports_root.iterdir()) if reports_root.exists() else set()
            result = run_live_capture(
                interface=capture_interface,
                refresh=args.refresh,
                view=args.view,
                bpf_filter=args.bpf_filter,
                save=args.save,
                reports_dir=args.reports_dir,
                open_report=False,
            )
            if result == 0 and reports_root.exists():
                candidates = [path for path in reports_root.iterdir() if path.is_dir() and path not in before]
                if not candidates:
                    candidates = [path for path in reports_root.iterdir() if path.is_dir()]
                if candidates:
                    session = max(candidates, key=lambda path: path.stat().st_mtime)
                    analysis_path = session / "analysis.json"
                    html_path = session / "report.html"
                    if analysis_path.exists() and html_path.exists():
                        report_data = json.loads(analysis_path.read_text(encoding="utf-8"))
                        pdf_path = write_pdf(report_data, session / "report.pdf")
                        attach_pdf_actions(html_path, pdf_path)
                        from .live import _restore_session_ownership
                        _restore_session_ownership(session)
                        print(f"PDF     : {pdf_path}")
                        if not args.no_open:
                            if _open_report(html_path):
                                print("Report opened automatically in your default browser.")
                            else:
                                print(f"Open the report manually: {html_path}")
            return result

        if args.command == "nmap":
            _print_banner()
            report = parse_nmap_xml(args.xml)
            print(f"Hosts      : {report['host_count']}")
            print(f"Open ports : {report['open_port_count']}")
            if args.json_path:
                print(f"JSON       : {write_json(report, args.json_path)}")
            else:
                print(json.dumps(report, indent=2))
            return 0

        if args.command == "correlate":
            _print_banner()
            capture = json.loads(Path(args.report_json).read_text(encoding="utf-8"))
            nmap = parse_nmap_xml(args.nmap_xml)
            result = correlate_reports(capture, nmap)
            if args.json_path:
                print(f"JSON : {write_json(result, args.json_path)}")
            else:
                print(json.dumps(result, indent=2))
            return 0
    except (CaptureError, NmapImportError, RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"PacketSageX error: {exc}", file=sys.stderr)
        return 2

    return 1
