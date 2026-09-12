from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import CaptureBackend
from ..models import PacketRecord


class ScapyBackend(CaptureBackend):
    def available(self) -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False

    def read(self, path: Path, *, tls_keylog: Path | None = None) -> Iterable[PacketRecord]:
        del tls_keylog  # Scapy fallback does not perform TLS key-log decryption.
        from scapy.all import DNS, DNSQR, Ether, ICMP, IP, IPv6, PcapReader, Raw, TCP, UDP

        def text(value: object) -> str:
            if isinstance(value, bytes):
                return value.decode("utf-8", "replace").rstrip(".")
            return str(value or "")

        with PcapReader(str(path)) as reader:
            for number, packet in enumerate(reader, 1):
                src = dst = ""
                protocol = packet.lastlayer().name.upper() if packet.lastlayer() else "UNKNOWN"
                if IP in packet:
                    src, dst = packet[IP].src, packet[IP].dst
                    protocol = str(packet[IP].proto)
                elif IPv6 in packet:
                    src, dst = packet[IPv6].src, packet[IPv6].dst
                elif Ether in packet:
                    src, dst = packet[Ether].src, packet[Ether].dst

                sport = dport = None
                flags = ""
                if TCP in packet:
                    sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
                    protocol = "TCP"
                    flags = str(packet[TCP].flags)
                elif UDP in packet:
                    sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)
                    protocol = "UDP"
                elif ICMP in packet:
                    protocol = "ICMP"

                dns_query = ""
                if DNS in packet and getattr(packet[DNS], "qd", None) and DNSQR in packet:
                    dns_query = text(packet[DNSQR].qname)
                    protocol = "DNS"

                http_host = http_uri = ""
                if Raw in packet and (sport in {80, 8080} or dport in {80, 8080}):
                    payload = bytes(packet[Raw].load)
                    try:
                        header = payload.decode("latin-1", "ignore")
                        for line in header.split("\r\n"):
                            if line.lower().startswith("host:"):
                                http_host = line.split(":", 1)[1].strip()
                            if line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                                parts = line.split()
                                if len(parts) > 1:
                                    http_uri = parts[1]
                    except Exception:
                        pass

                yield PacketRecord(
                    number=number,
                    timestamp=float(packet.time),
                    length=len(packet),
                    src=src,
                    dst=dst,
                    protocol=protocol,
                    src_port=sport,
                    dst_port=dport,
                    dns_query=dns_query,
                    http_host=http_host,
                    http_uri=http_uri,
                    tcp_flags=flags,
                )
