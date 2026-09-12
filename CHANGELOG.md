# Changelog

## 0.4.0 — 2026-09-12

- Added endpoint inventory with traffic scope, activity direction, packets, bytes, peers, and observed protocols.
- Added DNS analytics with query/response counts, unique domains, top queries, top clients, response codes, and NXDOMAIN counts.
- Added TLS/QUIC intelligence with visible SNI/server names and protocol-version metadata when TShark exposes it.
- Added live dashboard DNS/TLS/QUIC counters.
- Added Endpoint Inventory, DNS Analytics, and TLS / QUIC Intelligence sections to standalone HTML reports.
- Added normalized DNS response/TLS/QUIC metadata fields and automated tests.

## 0.3.1 — 2026-09-12

- Added automatic Scapy interface selection when `--interface any` is requested.
- Fixed application-classification false positives caused by ephemeral client ports.
- CI validated on Python 3.11, 3.12, and 3.13.

## 0.3.0 — 2026-09-12

- Added timestamped live-session report folders, capture/JSON/CSV/HTML outputs, automatic report opening, report search, and Top/Bottom sorting.

## 0.2.0 — 2026-09-12

- Added continuous live capture until Ctrl+C with dashboard/stream views.

## 0.1.0 — 2026-09-12

- Initial PCAP/PCAPNG analysis, Nmap XML correlation, classification, heuristics, reports, tests, and static web viewer.
