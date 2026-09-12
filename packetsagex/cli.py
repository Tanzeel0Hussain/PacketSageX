from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .analysis import analyze_capture
from .banner import BANNER, TAGLINE
from .capture import CaptureError
from .correlate import correlate_reports
from .live import run_live_capture
from .nmap_import import NmapImportError, parse_nmap_xml
from .reporting import write_csv, write_html, write_json


def _print_banner() -> None:
    print(BANNER)
    print(f"{TAGLINE}  |  v{__version__}\n")


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
    analyze.add_argument("--html", dest="html_path")

    live = sub.add_parser("live", help="Monitor live traffic until Ctrl+C")
    live.add_argument("-i", "--interface", default="any", help="Capture interface (default: any)")
    live.add_argument("--refresh", type=float, default=1.0, help="Dashboard refresh interval in seconds")
    live.add_argument("--view", choices=["dashboard", "stream"], default="dashboard")
    live.add_argument("--filter", dest="bpf_filter", help="Optional BPF capture filter, e.g. 'tcp or udp'")
    live.add_argument("--save", help="Optionally save captured traffic to a .pcap file")

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
        print(f"Scapy   : {scapy_state}")
        print("Live    : Scapy capture engine; runs until Ctrl+C")
        print("TLS keys: supported through TShark when you provide your own authorized key log")
        return 0

    try:
        if args.command == "analyze":
            _print_banner()
            report = analyze_capture(args.capture, backend=args.backend, tls_keylog=args.tls_keylog, packet_limit=args.limit)
            _summary(report)
            if args.json_path:
                print(f"JSON    : {write_json(report, args.json_path)}")
            if args.csv_path:
                print(f"CSV     : {write_csv(report, args.csv_path)}")
            if args.html_path:
                print(f"HTML    : {write_html(report, args.html_path)}")
            return 0

        if args.command == "live":
            _print_banner()
            print("Starting continuous live capture. Press Ctrl+C whenever you want to stop.\n")
            return run_live_capture(
                interface=args.interface,
                refresh=args.refresh,
                view=args.view,
                bpf_filter=args.bpf_filter,
                save=args.save,
            )

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
    except (CaptureError, NmapImportError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"PacketSageX error: {exc}", file=sys.stderr)
        return 2

    return 1
