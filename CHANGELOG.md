# Changelog

## 0.3.0 — 2026-09-12

- Added automatic timestamped report folders for every live capture session.
- Live sessions now save `capture.pcap`, `analysis.json`, `flows.csv`, and `report.html`.
- Added automatic HTML report opening when the user stops capture with Ctrl+C.
- Added sudo-aware ownership restoration for generated report files on Linux.
- Added full-flow search across Source, Destination, Protocol, Packets, Bytes, Likely Traffic, and Confidence.
- Added Top/Bottom sorting with selectable sort fields in the standalone HTML report.
- Added `--reports-dir` and `--no-open` live-mode options.
- Added tests for live report generation, unique session folders, and searchable report controls.
- Reduced false application labels by preventing shared ports such as 443 from identifying WhatsApp/Zoom/Discord without stronger evidence.

## 0.2.0 — 2026-09-12

- Added continuous `packetsagex live` capture mode that runs until Ctrl+C.
- Added refreshing terminal dashboard with packets, flows, bytes, PPS, Mbps, protocols, traffic categories, endpoints, and recent packets.
- Added `--view stream` for one-line-per-packet terminal output.
- Added optional BPF capture filters and `.pcap` saving during live monitoring.
- Reused the Scapy packet normalizer across offline and live analysis.
- Improved automatic offline backend fallback when TShark cannot read a capture.

## 0.1.0 — 2026-09-12

- Initial PacketSageX CLI and project architecture.
- TShark-first PCAP/PCAPNG metadata extraction with Scapy fallback.
- Flow aggregation and evidence-based traffic classification.
- Security heuristics for port-scan patterns, DNS/SYN bursts, and cleartext services.
- Nmap XML import and capture-to-scan correlation.
- JSON, CSV, and standalone HTML reports.
- Static GitHub Pages report viewer and Nmap XML inspector.
- CI tests and GitHub Pages deployment workflow.
