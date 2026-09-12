# PacketSageX

<p align="center"><img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" /></p>
<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

PacketSageX is an open-source defensive network-forensics project for PCAP/PCAPNG analysis, continuous live monitoring, flow intelligence, explainable application classification, Nmap XML correlation, DNS analytics, endpoint inventory, TLS/QUIC metadata analysis, security heuristics, and standalone reports.

> **Current release:** `v0.4.2`

## Main features

- Analyze `.pcap`, `.pcapng`, and `.cap` captures.
- Continuous `packetsagex live` monitoring until the user presses **Ctrl+C**.
- Automatic active-interface selection when Linux users request `--interface any` with the Scapy live engine.
- TShark-first offline analysis with automatic Scapy fallback where possible.
- On Linux, if TShark is blocked from reading an otherwise user-readable capture path, PacketSageX securely stages a temporary `0600` copy and retries automatically; the temporary copy is removed after analysis.
- TShark field parsing now uses native tab-separated output so valid captures no longer appear as a false `0 packets` result on builds that interpret a literal `\\t` separator differently.
- Bidirectional flow/session summaries with source, destination, protocol, packets, bytes, duration, likely traffic, confidence, and evidence.
- **Endpoint Inventory** with local/public/multicast scope, activity direction, peers, protocols, packets, and bytes.
- **DNS Analytics** with query/response counts, unique domains, top queries, top clients, response codes, and NXDOMAIN count.
- **TLS / QUIC Intelligence** with visible SNI/server names and version metadata when exposed by TShark.
- Evidence-based application classification for services such as YouTube, Google, WhatsApp, Discord, Zoom, Teams, Spotify, Steam, GitHub, and generic web traffic.
- Explainable defensive findings for port-scan patterns, SYN/DNS bursts, and common cleartext services.
- Nmap XML import and capture-to-scan correlation.
- JSON, CSV, and searchable standalone HTML reports.
- Timestamped report folder for every live session.
- HTML report automatically opens after Ctrl+C and includes search plus Top/Bottom sorting.
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

## Continuous live monitoring

```bash
sudo .venv/bin/packetsagex live --interface any
```

The scan runs continuously. Press **Ctrl+C** whenever you want to stop. PacketSageX then creates a new timestamped folder:

```text
reports/
└── 2026-09-12_10-21-00/
    ├── capture.pcap
    ├── analysis.json
    ├── flows.csv
    └── report.html
```

The HTML report opens automatically and contains:

```text
Overview
Security Findings
Endpoint Inventory
DNS Analytics
TLS / QUIC Intelligence
Flows
```

The flow table can search **Source, Destination, Protocol, Packets, Bytes, Likely Traffic, and Confidence**, and can sort Top/Bottom by selected fields.

Stream mode:

```bash
sudo .venv/bin/packetsagex live --interface any --view stream
```

## Offline capture analysis

```bash
packetsagex analyze capture.pcapng
```

Export reports:

```bash
packetsagex analyze capture.pcapng \
  --json reports/analysis.json \
  --csv reports/flows.csv \
  --html reports/report.html
```

Force a backend if needed:

```bash
packetsagex analyze capture.pcapng --backend tshark
packetsagex analyze capture.pcap --backend scapy
```

## Linux TShark compatibility

Some Linux security profiles allow TShark to read a capture from `/tmp` but deny direct access to the same user-readable file under another path. PacketSageX handles this automatically for offline TShark analysis: it first tries the original path, and only after a TShark permission-denied error does it make a private temporary copy, retry TShark, and delete that temporary copy when analysis finishes. PacketSageX does not disable AppArmor or other system security controls.

PacketSageX `v0.4.2` also fixes a separate TShark fields-output issue that could make a successfully opened capture produce `0` parsed packets. PacketSageX now relies on TShark's native tab-separated fields output, matching the parser's tab delimiter. See [`docs/TSHARK_COMPAT.md`](docs/TSHARK_COMPAT.md).

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
│   ├── live.py
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
