# PacketSageX

<p align="center">
  <img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" />
</p>

<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

PacketSageX is an open-source defensive network-analysis project for **PCAP/PCAPNG traffic intelligence, continuous live traffic monitoring, protocol/flow analysis, Nmap XML correlation, explainable traffic classification, security heuristics, and interactive report generation**.

It is designed for analysts, students, blue teams, labs, and administrators working with traffic they own or are authorized to inspect.

> **Current release:** `v0.3.1` — continuous live capture, automatic interface selection, timestamped session reports, searchable/sortable HTML results, safer traffic classification, and multi-version CI testing.

## What PacketSageX can do

- Read `.pcap`, `.pcapng`, and `.cap` captures.
- Monitor **live network traffic continuously until Ctrl+C**.
- Accept `--interface any` and automatically select a usable Scapy network interface on Linux.
- Prefer **TShark/Wireshark dissectors** for broad offline protocol visibility.
- Automatically fall back to **Scapy** for offline analysis when TShark cannot read a capture.
- Build bidirectional flow/session summaries.
- Show source/destination endpoints, ports, protocols, packet counts, byte counts, and duration.
- Infer likely traffic such as web, DNS, YouTube, Netflix, WhatsApp, Discord, Zoom, Teams, Spotify, Steam, GitHub, and other services when evidence exists.
- Report a **confidence score and evidence** instead of pretending encrypted traffic can always be identified exactly.
- Avoid treating common/shared ports such as `443` as enough evidence to identify a specific application.
- Flag explainable patterns such as possible port scans, SYN bursts, DNS bursts, and use of common cleartext service ports.
- Import Nmap XML (`nmap -oX`) and correlate discovered hosts/services with capture endpoints.
- Export JSON, CSV, and standalone HTML reports.
- Automatically create a **new timestamped report folder for every live session**.
- Automatically open the generated HTML report after live capture is stopped.
- Search flow results by **Source, Destination, Protocol, Packets, Bytes, Likely Traffic, and Confidence**.
- Sort report flows using **Top / Bottom** controls by bytes, packets, confidence, endpoints, protocol, or likely traffic.
- Use an authorized TLS key log with TShark for sessions that are legitimately decryptable.
- Provide a static GitHub Pages report viewer and Nmap XML inspector.

## Important limitation

Modern traffic is often encrypted. PacketSageX **does not break TLS, WhatsApp encryption, VPN encryption, or cryptography**. Application labels are evidence-based estimates derived from metadata such as DNS, SNI, HTTP Host, endpoints, ports, protocol, and flow behavior. Shared CDNs, encrypted DNS, ECH, NAT, VPNs, QUIC, and missing hostname metadata can reduce certainty.

For authorized lab traffic, a user-supplied TLS key log can be passed to TShark. See [`docs/DECRYPTION.md`](docs/DECRYPTION.md).

## Project layout

```text
PacketSageX/
├── packetsagex/
│   ├── capture/              # TShark + Scapy capture backends
│   ├── intelligence/         # traffic classifier + signatures
│   ├── analysis.py           # offline flow/session aggregation
│   ├── live.py               # continuous live monitor + session reports
│   ├── interfaces.py         # automatic live interface selection
│   ├── security.py           # explainable defensive heuristics
│   ├── nmap_import.py        # Nmap XML importer
│   ├── correlate.py          # PCAP ↔ Nmap correlation
│   ├── reporting.py          # JSON/CSV/searchable HTML exports
│   └── cli.py                # terminal interface
├── web/                      # GitHub Pages viewer
├── tests/                    # automated tests
├── sample_data/              # safe sample report + Nmap XML
├── docs/                     # architecture/rules/live/decryption docs
├── reports/                  # local generated reports (gitignored)
└── .github/workflows/        # CI + Pages deployment
```

## Installation — Ubuntu / Debian / Kali

Recommended because TShark provides the richest offline protocol dissection:

```bash
sudo apt update
sudo apt install -y python3 python3-venv wireshark-common tshark git

git clone https://github.com/Tanzeel0Hussain/PacketSageX.git
cd PacketSageX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

Verify:

```bash
packetsagex --version
packetsagex doctor
```

Expected current version:

```text
PacketSageX 0.3.1
```

## Installation — Windows 10/11

1. Install Python 3.11+ from Python.org and enable **Add Python to PATH**.
2. Install Wireshark and make sure **TShark** is included.
3. Open PowerShell:

```powershell
git clone https://github.com/Tanzeel0Hussain/PacketSageX.git
cd PacketSageX
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
packetsagex doctor
```

If PowerShell blocks virtual-environment activation for the current process:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

## Live capture — recommended workflow

On Linux, start continuous monitoring with:

```bash
sudo .venv/bin/packetsagex live --interface any
```

`any` is treated as an automatic-selection request for Scapy. PacketSageX chooses a usable real interface such as Wi-Fi or Ethernet and keeps monitoring until you press:

```text
Ctrl+C
```

While running, the terminal dashboard shows live packet count, flow count, bytes, packet rate, estimated Mbps, protocols, traffic categories, top endpoints, and recent packets.

For one-line-per-packet output:

```bash
sudo .venv/bin/packetsagex live --interface any --view stream
```

Optional BPF filter:

```bash
sudo .venv/bin/packetsagex live --interface any --filter "tcp or udp"
```

To choose a specific interface manually:

```bash
ip link
sudo .venv/bin/packetsagex live --interface wlp2s0
```

See [`docs/LIVE_CAPTURE.md`](docs/LIVE_CAPTURE.md) for more details.

## Automatic live-session reports

Every live scan creates its own timestamped folder under `reports/`.

Example:

```text
reports/
├── 2026-09-12_10-21-00/
│   ├── capture.pcap
│   ├── analysis.json
│   ├── flows.csv
│   └── report.html
└── 2026-09-12_10-30-44/
    ├── capture.pcap
    ├── analysis.json
    ├── flows.csv
    └── report.html
```

When Ctrl+C is pressed, PacketSageX finalizes the session and attempts to open `report.html` automatically in the default browser.

Disable automatic browser opening with:

```bash
sudo .venv/bin/packetsagex live --interface any --no-open
```

Use another reports root folder with:

```bash
sudo .venv/bin/packetsagex live --interface any --reports-dir my_reports
```

## Searchable and sortable HTML report

The generated standalone HTML report includes a full-flow search box covering:

- Source
- Destination
- Protocol
- Packets
- Bytes
- Likely Traffic
- Confidence

The report also supports sorting by:

- Bytes
- Packets
- Confidence
- Source
- Destination
- Protocol
- Likely Traffic

Use **Top ↓** for highest-first / descending results and **Bottom ↑** for lowest-first / ascending results.

## Analyze an existing capture

Basic analysis:

```bash
packetsagex analyze capture.pcapng
```

PacketSageX uses the automatic backend by default. It prefers TShark and can fall back to Scapy when appropriate.

Export all common report formats:

```bash
mkdir -p reports
packetsagex analyze capture.pcapng \
  --json reports/analysis.json \
  --csv reports/flows.csv \
  --html reports/report.html
```

Force a backend:

```bash
packetsagex analyze capture.pcapng --backend tshark
packetsagex analyze capture.pcap --backend scapy
```

Limit packets during development:

```bash
packetsagex analyze large_capture.pcapng --limit 5000 --json quick.json
```

## Authorized TLS key-log support

```bash
packetsagex analyze my_lab_capture.pcapng \
  --tls-keylog sslkeys.log \
  --html decrypted-metadata-report.html
```

This only works when the supplied secrets legitimately match the captured TLS sessions and TShark can use them.

## Nmap integration

PacketSageX imports Nmap results; it does not need to launch a scan itself.

Create XML for a system you are authorized to test:

```bash
nmap -sV -oX scan.xml 192.168.1.10
```

Import it:

```bash
packetsagex nmap scan.xml --json nmap.json
```

Correlate a PacketSageX capture report with Nmap XML:

```bash
packetsagex correlate reports/analysis.json scan.xml --json correlation.json
```

## Traffic classification

PacketSageX currently combines:

- DNS query names
- TLS SNI when visible
- HTTP Host metadata when visible
- application-associated ports where meaningful
- protocol names
- flow packet volume as a weak supporting signal

Example interpretation:

```text
Likely traffic : YouTube / Google Video
Confidence     : 91%
Evidence       : domain hint: googlevideo.com; service port: 443; protocol: QUIC
```

A label means **likely**, not guaranteed. Common client/ephemeral ports and shared service ports are intentionally treated cautiously to reduce false positives. See [`docs/RULES.md`](docs/RULES.md).

## GitHub Pages web version

The `web/` directory is intentionally static so it can run on GitHub Pages without a server. It can:

- load PacketSageX JSON analysis reports locally in the browser,
- visualize traffic categories and flow data,
- display security findings,
- inspect Nmap XML locally.

The web build does **not** replace the CLI capture engine. Raw PCAP/PCAPNG and live capture analysis remain local to the Python/TShark/Scapy tool.

After GitHub Pages is enabled for the included Actions workflow, the expected site address is:

```text
https://tanzeel0hussain.github.io/PacketSageX/
```

## Run tests

Install development dependencies and run the test suite:

```bash
pip install -e ".[dev]"
pytest -q
```

GitHub Actions currently tests the project against Python **3.11, 3.12, and 3.13**.

## Sample files

```bash
packetsagex nmap sample_data/nmap_sample.xml
```

The browser demo also contains a built-in safe sample dataset. No real third-party packet capture is committed to this repository.

## Recent v0.3.x improvements

- Continuous live monitoring until Ctrl+C.
- Automatic Scapy interface selection for `--interface any`.
- Timestamped report folders for every live session.
- Automatic PCAP, JSON, CSV, and HTML generation.
- Automatic browser opening after live capture stops.
- Searchable and sortable standalone HTML flow table.
- TShark-to-Scapy offline fallback improvements.
- Safer application classification to reduce false positives caused by shared or ephemeral ports.
- Expanded automated tests and CI validation on multiple Python versions.

## Roadmap

The next development phase focuses on:

1. Richer protocol intelligence for **DNS, TLS, QUIC, HTTP, ARP, DHCP, ICMP, SSH, and SMB**.
2. Better **host/endpoint inventory** with local/remote identification and per-host statistics.
3. **DNS analytics** such as top queried domains, query counts, and response/error information where available.
4. **Timeline analytics** showing traffic volume and events over time.
5. Stronger application signatures and explainable confidence scoring.
6. More advanced defensive anomaly scoring and security findings.
7. Improved report charts and visualization while keeping reports standalone/offline.
8. Stronger Nmap-to-PCAP correlation.
9. Larger test coverage and safe sample datasets.

## Ethical use

Use PacketSageX only on captures, systems, and scan results that you own or have explicit permission to analyze. Do not upload private packet captures, credentials, TLS key logs, or other sensitive data to public repositories.

## License

MIT — see [`LICENSE`](LICENSE).

---

Built and maintained by **Tanzeel Hussain**.
