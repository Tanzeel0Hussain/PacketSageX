# Changelog

## 0.4.2 — 2026-09-12

- Fixed a TShark fields-output parsing bug that could produce `Backend: tshark` with `0` packets even when the staged capture was valid and readable.
- PacketSageX now relies on TShark's native tab-separated fields output instead of passing a literal `\\t` separator value that some TShark builds interpret incorrectly.
- Added a regression test that feeds a real tab-separated TShark-style row through the parser and verifies packet, endpoint, TLS SNI, and TLS-version extraction.

## 0.4.1 — 2026-09-12

- Added a secure TShark path-permission compatibility retry for Linux environments where TShark can read `/tmp` but is denied access to an otherwise user-readable capture elsewhere.
- PacketSageX now copies the capture (and optional TLS key log) into a private temporary directory with `0600` file permissions only after a TShark permission-denied error, retries analysis, and removes the temporary files automatically.
- Added regression coverage for the TShark staging path. PacketSageX does not disable AppArmor or other host security controls.

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
