# Live Capture Mode

PacketSageX can monitor traffic continuously in the terminal. The capture keeps running until the user presses **Ctrl+C**.

## Dashboard view

```bash
sudo .venv/bin/packetsagex live --interface any
```

The dashboard refreshes in place and shows packet count, flow count, bytes, packets/second, Mbps, top protocols, likely traffic categories, top endpoints, and recent packets.

## Stream view

To print every captured packet as a new terminal line:

```bash
sudo .venv/bin/packetsagex live --interface any --view stream
```

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

## Save while monitoring

Live mode can save the same traffic to a classic PCAP file for later full analysis:

```bash
sudo .venv/bin/packetsagex live --interface any --save /tmp/packetsagex-live.pcap
```

After stopping with Ctrl+C:

```bash
sudo chown "$USER":"$USER" /tmp/packetsagex-live.pcap
packetsagex analyze /tmp/packetsagex-live.pcap
```

## Permission note

Packet capture requires OS-level capture permission. On Linux, if normal execution is denied, run the virtual-environment executable through sudo as shown above. PacketSageX disables promiscuous mode in live mode by default and only observes traffic visible to the selected interface.
