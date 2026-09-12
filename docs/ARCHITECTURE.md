# PacketSageX Architecture

PacketSageX separates capture dissection, flow aggregation, traffic intelligence, security heuristics, external scan import, and reporting.

1. **Capture layer** selects TShark first and Scapy as a fallback.
2. **Normalization layer** converts packets into `PacketRecord` objects.
3. **Flow engine** groups bidirectional endpoint/port/protocol tuples.
4. **Intelligence engine** applies extensible metadata signatures and produces a confidence score plus evidence.
5. **Security engine** raises explainable heuristic findings such as possible port scanning, DNS bursts, SYN bursts, and cleartext-service exposure.
6. **Nmap importer** reads existing `-oX` output without launching a scan.
7. **Correlation engine** matches observed capture endpoints with imported Nmap hosts/services.
8. **Reporting layer** exports JSON, CSV, and standalone HTML.

## Why TShark first?

Wireshark already has a mature ecosystem of protocol dissectors. PacketSageX uses TShark metadata when available instead of attempting to reimplement every network protocol. Scapy provides a useful fallback for common packet formats.

## Classification model

Application labels are probabilistic. A flow can be labelled from DNS names, TLS SNI, HTTP host metadata, service ports, dissector protocol, and flow patterns. Shared CDNs, VPNs, encrypted DNS, ECH, NAT, and modern encrypted transports can reduce certainty, so reports keep both **confidence** and **evidence**.
