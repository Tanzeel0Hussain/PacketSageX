# PacketSageX

<p align="center"><img src="web/assets/logo.svg" width="128" alt="PacketSageX logo" /></p>
<p align="center"><strong>Network Traffic Intelligence & Forensics Platform</strong></p>

## What is PacketSageX?

PacketSageX is an open-source defensive network traffic analysis and forensics tool.

It can monitor live network traffic or analyze saved PCAP/PCAPNG captures and show useful information such as packets, flows, source and destination addresses, protocols, DNS activity, endpoints, likely traffic categories, security findings, and available TLS/QUIC metadata.

When a live capture is stopped with **Ctrl+C**, PacketSageX saves the capture and creates JSON, CSV, HTML, and professional PDF reports inside a timestamped folder under `reports/`.

PacketSageX is designed for defensive analysis of networks and captures that you own or have permission to inspect. It does not break TLS, VPN, WhatsApp, or other encryption.

## Install and Run

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

Start live network monitoring:

```bash
cd ~/PacketSageX
source .venv/bin/activate
sudo .venv/bin/packetsagex live --interface any
```

PacketSageX will keep monitoring traffic until you press:

```text
Ctrl + C
```

After stopping, a new report folder is created like this:

```text
reports/
└── 2026-09-12_11-45-31/
    ├── capture.pcap
    ├── analysis.json
    ├── flows.csv
    ├── report.html
    └── report.pdf
```

## Open the Latest HTML Report

```bash
cd ~/PacketSageX
LATEST=$(find reports -mindepth 1 -maxdepth 1 -type d | sort | tail -1)
xdg-open "$LATEST/report.html"
```
