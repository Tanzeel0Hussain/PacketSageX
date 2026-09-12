# Live Capture Mode

PacketSageX can monitor traffic continuously in the terminal. The capture keeps running until the user presses **Ctrl+C**.

## Dashboard view

```bash
sudo .venv/bin/packetsagex live --interface any
```

The dashboard refreshes in place and shows packet count, flow count, bytes, packets/second, Mbps, top protocols, likely traffic categories, top endpoints, and recent packets.

There is no fixed 30-second timer. Capture continues until **Ctrl+C**.

## Automatic session reports

Every live scan creates a new timestamped directory under `reports/`.

Example:

```text
reports/
├── 2026-09-12_10-20-41/
│   ├── capture.pcap
│   ├── analysis.json
│   ├── flows.csv
│   └── report.html
├── 2026-09-12_10-31-08/
│   ├── capture.pcap
│   ├── analysis.json
│   ├── flows.csv
│   └── report.html
```

If two sessions start in the same second, PacketSageX adds a numeric suffix so an existing folder is never overwritten.

When the user presses **Ctrl+C**, PacketSageX automatically:

1. stops capture,
2. closes the PCAP file,
3. creates JSON, CSV, and HTML reports,
4. restores file ownership to the original desktop user when the command was started with `sudo`,
5. opens `report.html` in the default browser.

Use `--no-open` if you do not want the browser to open automatically:

```bash
sudo .venv/bin/packetsagex live --interface any --no-open
```

Use another report root folder if needed:

```bash
sudo .venv/bin/packetsagex live --interface any --reports-dir ~/PacketSageX/reports
```

## Searchable HTML flow report

The generated HTML report includes a flow table with:

- Source
- Destination
- Protocol
- Packets
- Bytes
- Likely Traffic
- Confidence

The search box matches any of those columns. The report also includes a sort-field selector plus **Top** and **Bottom** buttons. For numeric fields such as bytes, packets, and confidence, Top shows the largest values first and Bottom shows the smallest values first.

## Stream view

To print every captured packet as a new terminal line:

```bash
sudo .venv/bin/packetsagex live --interface any --view stream
```

The timestamped report folder is still generated after Ctrl+C.

## Choose an interface

List interfaces with:

```bash
ip link
```

Then monitor a specific interface, for example:

```bash
sudo .venv/bin/packetsagex live --interface wlp2s0
```

## Optional capture filter

PacketSageX accepts a BPF capture filter through Scapy/libpcap:

```bash
sudo .venv/bin/packetsagex live --interface any --filter "tcp or udp"
```

## Custom PCAP save path

By default, live capture is saved as `capture.pcap` inside the timestamped session directory.

You can override only the PCAP location:

```bash
sudo .venv/bin/packetsagex live \
  --interface any \
  --save /tmp/packetsagex-live.pcap
```

The JSON, CSV, and HTML reports are still placed inside the timestamped `reports/<date_time>/` folder.

## Permission note

Packet capture requires OS-level capture permission. On Linux, if normal execution is denied, run the virtual-environment executable through sudo as shown above. PacketSageX disables promiscuous mode in live mode by default and only observes traffic visible to the selected interface.

Use PacketSageX only on networks and traffic that you own or are explicitly authorized to inspect.
