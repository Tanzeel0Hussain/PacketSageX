# PacketSageX

<p align="center">
  <img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" />
</p>

<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

PacketSageX is an open-source defensive network-analysis project for **PCAP/PCAPNG traffic intelligence, protocol/flow analysis, Nmap XML correlation, explainable traffic classification, security heuristics, and report generation**.

It is designed for analysts, students, blue teams, labs, and administrators working with traffic they own or are authorized to inspect.

> **Current release:** `v0.1.0` — foundation release. PacketSageX already performs real analysis, but the signature database and advanced protocol modules will continue to grow.

## What PacketSageX can do

- Read `.pcap`, `.pcapng`, and `.cap` captures.
- Prefer **TShark/Wireshark dissectors** for broad protocol visibility.
- Fall back to **Scapy** for common packet analysis.
- Build bidirectional flow/session summaries.
- Show source/destination endpoints, ports, protocols, packet counts, byte counts, and duration.
- Infer likely traffic such as web, DNS, YouTube, Netflix, WhatsApp, Discord, Zoom, Teams, Spotify, Steam, GitHub, and other services when evidence exists.
- Report a **confidence score and evidence** instead of pretending encrypted traffic can always be identified exactly.
- Flag explainable patterns such as possible port scans, SYN bursts, DNS bursts, and use of common cleartext service ports.
- Import Nmap XML (`nmap -oX`) and correlate discovered hosts/services with capture endpoints.
- Export JSON, CSV, and standalone HTML reports.
- Use an authorized TLS key log with TShark for sessions that are legitimately decryptable.
- Provide a static GitHub Pages report viewer and Nmap XML inspector.

## Important limitation

Modern traffic is often encrypted. PacketSageX **does not break TLS, WhatsApp encryption, VPN encryption, or cryptography**. Application labels can be inferred from metadata such as DNS, SNI, endpoints, ports, protocol, and flow behavior, but shared CDNs, encrypted DNS, ECH, NAT, VPNs, and QUIC can reduce certainty.

For authorized lab traffic, a user-supplied TLS key log can be passed to TShark. See [`docs/DECRYPTION.md`](docs/DECRYPTION.md).

## Project layout

```text
PacketSageX/
├── packetsagex/
│   ├── capture/              # TShark + Scapy capture backends
│   ├── intelligence/         # traffic classifier + signatures
│   ├── analysis.py           # flow/session aggregation
│   ├── security.py           # explainable defensive heuristics
│   ├── nmap_import.py        # Nmap XML importer
│   ├── correlate.py          # PCAP ↔ Nmap correlation
│   ├── reporting.py          # JSON/CSV/HTML exports
│   └── cli.py                # terminal interface
├── web/                      # GitHub Pages viewer
├── tests/                    # automated tests
├── sample_data/              # safe sample report + Nmap XML
├── docs/                     # architecture/rules/decryption docs
└── .github/workflows/        # CI + Pages deployment
```

## Installation — Ubuntu / Debian / Kali

Recommended because TShark provides the richest protocol dissection:

```bash
sudo apt update
sudo apt install -y python3 python3-venv wireshark-common tshark

git clone https://github.com/Tanzeel0Hussain/PacketSageX.git
cd PacketSageX
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

Verify:

```bash
packetsagex doctor
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

## Analyze a capture

Basic analysis:

```bash
packetsagex analyze capture.pcapng
```

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
- ports and protocol names
- flow packet volume as a weak supporting signal

Example interpretation:

```text
Likely traffic : YouTube / Google Video
Confidence     : 91%
Evidence       : domain hint: googlevideo.com; service port: 443; protocol: QUIC
```

A label means **likely**, not guaranteed. See [`docs/RULES.md`](docs/RULES.md).

## GitHub Pages web version

The `web/` directory is intentionally static so it can run on GitHub Pages without a server. It can:

- load PacketSageX JSON analysis reports locally in the browser,
- visualize traffic categories and flow data,
- display security findings,
- inspect Nmap XML locally.

The web build does **not** replace the CLI PCAP engine. Raw PCAP/PCAPNG analysis remains in the Python/TShark tool.

After GitHub Pages is enabled for the included Actions workflow, the site will use:

```text
https://tanzeel0hussain.github.io/PacketSageX/
```

## Run tests

```bash
pip install -e ".[dev]"
pytest -q
```

## Sample files

```bash
packetsagex nmap sample_data/nmap_sample.xml
```

The browser demo also contains a built-in safe sample dataset. No real third-party packet capture is committed to this repository.

## Roadmap

Planned expansion includes richer IPv6/ARP/DHCP/SMB/SSH/TLS/QUIC intelligence, configurable user rule packs, JA4/flow fingerprints where legally and technically appropriate, stronger anomaly scoring, DNS analytics, timeline views, additional report visualizations, endpoint inventory, more Nmap correlation, safe PCAP sanitization tools, and larger tested signature packs.

## Ethical use

Use PacketSageX only on captures, systems, and scan results that you own or have explicit permission to analyze. Do not upload private packet captures, credentials, TLS key logs, or other sensitive data to public repositories.

## License

MIT — see [`LICENSE`](LICENSE).

---

Built and maintained by **Tanzeel Hussain**.
