# PacketSageX

<p align="center"><img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" /></p>
<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

## What is PacketSageX?

PacketSageX is a defensive network traffic analysis and forensics tool. It can monitor live traffic or analyze Wireshark `.pcap`, `.pcapng`, and `.cap` files to show packets, flows, endpoints, protocols, DNS activity, likely traffic types, and security findings.

Use it only with captures and networks that you own or have permission to inspect. PacketSageX does not break TLS, VPN, WhatsApp, or other encryption.

## Live Mini Analyzer

A small browser version is available on GitHub Pages:

**https://tanzeel0hussain.github.io/PacketSageX/**

The live mini analyzer is built with HTML, CSS, and JavaScript because those technologies fit GitHub Pages better than Python. It can inspect common Wireshark PCAP/PCAPNG captures locally in the browser. The capture is not uploaded to a server.

The full CLI is still the main version because TShark, Scapy, professional PDF reports, and deeper analysis need the desktop environment.

## Install

Ubuntu / Debian / Kali:

```bash
sudo apt update
sudo apt install -y python3 python3-venv wireshark-common tshark git

git clone https://github.com/Tanzeel0Hussain/PacketSageX.git
cd PacketSageX

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Check installation:

```bash
packetsagex --version
python -m pytest -q
packetsagex doctor
```

## Analyze a Wireshark File

Example:

```bash
cd ~/PacketSageX
source .venv/bin/activate
packetsagex wireshark ~/Downloads/capture.pcap
```

You can also use:

```bash
packetsagex wireshark ~/Downloads/capture.pcapng
```

PacketSageX creates a report folder containing:

```text
analysis.json
flows.csv
packets.csv
report.html
report.pdf
```

## Live Network Monitoring

```bash
cd ~/PacketSageX
source .venv/bin/activate
sudo .venv/bin/packetsagex live --interface any
```

Press `Ctrl + C` to stop and generate the reports.

## Open the Latest HTML Report

```bash
cd ~/PacketSageX
LATEST=$(find reports -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
xdg-open "$LATEST/report.html"
```
