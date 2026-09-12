# PacketSageX

<p align="center"><img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" /></p>
<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

## What is PacketSageX?

PacketSageX is an open-source defensive network traffic analysis and forensics tool.

It can monitor live traffic and it can also analyze packet-capture files saved or exported from **Wireshark** (`.pcap`, `.pcapng`, `.cap`). PacketSageX examines packets, flows, source and destination addresses, protocols, ports, DNS activity, visible HTTP/TLS/QUIC metadata, endpoints, likely traffic categories, and defensive security findings.

For Wireshark files, PacketSageX also creates a searchable **Packet Explorer** in the HTML report and a `packets.csv` file with packet-level details and short packet descriptions.

PacketSageX is for captures and networks that you own or have permission to inspect. It does not break TLS, VPN, WhatsApp, or other encryption.

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

Check the installation:

```bash
packetsagex --version
python -m pytest -q
packetsagex doctor
```

## Analyze a Wireshark File

Save or export the capture from Wireshark as `.pcap`, `.pcapng`, or `.cap`, then run:

```bash
cd ~/PacketSageX
source .venv/bin/activate

packetsagex wireshark "/path/to/capture.pcapng"
```

Example for a file in Downloads:

```bash
packetsagex wireshark ~/Downloads/capture.pcapng
```

PacketSageX analyzes the capture and creates a new folder like:

```text
reports/
└── wireshark_2026-09-12_12-00-00/
    ├── analysis.json
    ├── flows.csv
    ├── packets.csv
    ├── report.html
    └── report.pdf
```

The HTML report contains Overview, Security, Endpoints, DNS, TLS / QUIC, Flows, and **Packets** tabs. The Packets tab can be searched by packet number, source, destination, protocol, size, or packet description.

## Run Live Monitoring

```bash
cd ~/PacketSageX
source .venv/bin/activate
sudo .venv/bin/packetsagex live --interface any
```

Press:

```text
Ctrl + C
```

to stop the capture and generate the report files.

## Open the Latest HTML Report

```bash
cd ~/PacketSageX
LATEST=$(find reports -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
xdg-open "$LATEST/report.html"
```
