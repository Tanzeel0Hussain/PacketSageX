# PacketSageX

<p align="center"><img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" /></p>
<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

PacketSageX is an open-source defensive network-forensics project for PCAP/PCAPNG analysis, continuous live monitoring, flow intelligence, explainable application classification, Nmap XML correlation, DNS analytics, endpoint inventory, TLS/QUIC metadata analysis, security heuristics, and professional standalone reports.

> **Current release:** `v0.4.3`

## Main features

- Analyze `.pcap`, `.pcapng`, and `.cap` captures.
- Continuous `packetsagex live` monitoring until the user presses **Ctrl+C**.
- Automatic active-interface selection when Linux users request `--interface any` with the Scapy live engine.
- TShark-first offline analysis with automatic Scapy fallback where possible.
- Linux TShark path-permission compatibility through secure temporary staging without disabling host security controls.
- Native TShark fields parsing that avoids false `0 packets` results on affected builds.
- Bidirectional flow/session summaries with source, destination, protocol, packets, bytes, duration, likely traffic, confidence, and evidence.
- **Endpoint Inventory** with local/public/multicast scope, activity direction, peers, protocols, packets, and bytes.
- **DNS Analytics** with query/response counts, unique domains, top queries, top clients, response codes, and NXDOMAIN count.
- **TLS / QUIC Intelligence** with visible SNI/server names and version metadata when exposed by TShark.
- Evidence-based application classification for services such as YouTube, Google, WhatsApp, Discord, Zoom, Teams, Spotify, Steam, GitHub, and generic web traffic.
- Explainable defensive findings for port-scan patterns, SYN/DNS bursts, and common cleartext services.
- Nmap XML import and capture-to-scan correlation.
- JSON, CSV, searchable tabbed HTML, and **native professional PDF** reports.
- Timestamped report folder for every live session.
- HTML report automatically opens after Ctrl+C.
- **Cyber-console terminal branding** with a large `PACKETSAGEX` banner, status line, and ANSI color in interactive terminals.
- **Tabbed HTML report** with Overview, Security, Endpoints, DNS, TLS / QUIC, and Flows sections.
- HTML actions for **Open Professional PDF** and **Save PDF** instead of browser Print-to-PDF.
- Native PDF cover page, executive summary, findings, inventory, DNS, TLS/QUIC, complete flow tables, repeated table headers, page numbers, and PacketSageX headers/footers.
- Flow search across Source, Destination, Protocol, Packets, Bytes, Likely Traffic, and Confidence, plus Top/Bottom sorting.
- Authorized TLS key-log support through TShark for sessions that the user is legitimately allowed to decrypt.
- CI tests on Python 3.11, 3.12, and 3.13.

## Important limitation

PacketSageX does **not** break TLS, WhatsApp encryption, VPN encryption, or other cryptography. Application labels are inferred from metadata and can be uncertain when traffic uses shared CDNs, encrypted DNS, ECH, NAT, VPNs, or other privacy layers.

## Installation — Ubuntu / Debian / Kali

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

For development/tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```

Verify runtime:

```bash
packetsagex doctor
```

`doctor` now also shows whether the native professional PDF engine is available.

## Continuous live monitoring

```bash
sudo .venv/bin/packetsagex live --interface any
```

The scan runs continuously. Press **Ctrl+C** whenever you want to stop. PacketSageX creates a new timestamped folder:

```text
reports/
└── 2026-09-12_10-21-00/
    ├── capture.pcap
    ├── analysis.json
    ├── flows.csv
    ├── report.html
    └── report.pdf
```

The native PDF is generated before the HTML report is opened, so the HTML can immediately provide **Open Professional PDF** and **Save PDF** actions.

Stream mode:

```bash
sudo .venv/bin/packetsagex live --interface any --view stream
```

## Tabbed HTML report

The standalone HTML report uses tabs instead of placing every section on one long page:

```text
Overview
Security
Endpoints
DNS
TLS / QUIC
Flows
```

The **Flows** tab keeps search and Top/Bottom sorting controls. The HTML dashboard is intended for interactive investigation, while the native PDF is intended for sharing, archiving, printing, assignments, and professional evidence.

## Professional PDF reports

PacketSageX `v0.4.3` no longer relies on the browser's Print / Save PDF output for its formal report. The PDF is generated directly from the analysis data using a dedicated report engine, so it looks like a normal forensic document rather than a printed web page.

The PDF includes:

- Branded PacketSageX cover page.
- Capture source, backend, interface, and generation time.
- Executive summary with packet, flow, byte, DNS, and finding totals.
- Traffic classification summary.
- Security findings and supporting evidence.
- Endpoint inventory.
- DNS analytics and top queries.
- TLS / QUIC intelligence and visible SNI data.
- Complete flow details.
- Repeated table headings for long tables.
- Page numbers and branded headers/footers.
- Clean A4 landscape pagination with no browser URL/date print chrome.

See [`docs/PDF_REPORTS.md`](docs/PDF_REPORTS.md) for details.

## Offline capture analysis

```bash
packetsagex analyze capture.pcapng
```

Export JSON, CSV, HTML and an automatically generated sibling PDF:

```bash
packetsagex analyze capture.pcapng \
  --json reports/analysis.json \
  --csv reports/flows.csv \
  --html reports/report.html
```

The command above creates both:

```text
reports/report.html
reports/report.pdf
```

Generate only a native PDF at a chosen path:

```bash
packetsagex analyze capture.pcapng \
  --backend tshark \
  --pdf reports/forensics-report.pdf
```

Choose separate HTML and PDF filenames:

```bash
packetsagex analyze capture.pcapng \
  --backend tshark \
  --html reports/session.html \
  --pdf reports/session-forensics.pdf
```

Force a capture backend if needed:

```bash
packetsagex analyze capture.pcapng --backend tshark
packetsagex analyze capture.pcap --backend scapy
```

## Linux TShark compatibility

Some Linux security profiles allow TShark to read a capture from `/tmp` but deny direct access to the same user-readable file under another path. PacketSageX handles this automatically for offline TShark analysis: it first tries the original path, and only after a TShark permission-denied error does it make a private temporary copy, retry TShark, and delete that temporary copy when analysis finishes. PacketSageX does not disable AppArmor or other system security controls.

PacketSageX also uses TShark's native tab-separated fields output so a successfully opened capture is not incorrectly reported as `0` parsed packets. See [`docs/TSHARK_COMPAT.md`](docs/TSHARK_COMPAT.md).

## DNS intelligence

PacketSageX records DNS query names available in the capture and summarizes query volume, unique domains, clients, response codes, and NXDOMAIN responses. Encrypted DNS such as DoH/DoT may hide normal DNS metadata.

## TLS / QUIC intelligence

When TShark exposes the metadata, PacketSageX records visible TLS SNI/server names and TLS/QUIC version fields. This is metadata analysis; it does not defeat encryption.

## Endpoint inventory

Each observed endpoint can include scope (`private/local`, `public`, `multicast`, `link-local`, etc.), sent/received traffic, peer count, observed protocols, and total packets/bytes.

## Nmap integration

For a system you are authorized to test:

```bash
nmap -sV -oX scan.xml 192.168.1.10
packetsagex nmap scan.xml --json nmap.json
packetsagex correlate reports/analysis.json scan.xml --json correlation.json
```

## Authorized TLS key log

```bash
packetsagex analyze my_lab_capture.pcapng \
  --tls-keylog sslkeys.log \
  --html decrypted-metadata-report.html
```

The supplied secrets must legitimately match the captured sessions.

## Project layout

```text
PacketSageX/
├── packetsagex/
│   ├── capture/
│   ├── intelligence/
│   │   ├── analytics.py
│   │   ├── classifier.py
│   │   └── signatures.json
│   ├── analysis.py
│   ├── banner.py
│   ├── live.py
│   ├── pdf_report.py
│   ├── reporting.py
│   ├── security.py
│   ├── nmap_import.py
│   └── correlate.py
├── web/
├── tests/
├── sample_data/
├── docs/
└── .github/workflows/
```

## Roadmap

Next work includes timeline analytics and traffic spikes, richer protocol intelligence, stronger DNS anomaly analysis, expanded security scoring, improved Nmap correlation, report charts, configurable rule packs, and larger tested signature packs.

## Ethical use

Use PacketSageX only on captures, systems, and scan results that you own or have explicit permission to analyze. Never commit private captures, credentials, or TLS key logs to a public repository.

## License

MIT — see [`LICENSE`](LICENSE).

---

Built and maintained by **Tanzeel Hussain**.
