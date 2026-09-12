from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .base import CaptureBackend
from ..models import PacketRecord


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace').rstrip('.')
    return str(value or '')


def packet_to_record(packet: object, number: int) -> PacketRecord:
    from scapy.all import DNS, DNSQR, Ether, ICMP, IP, IPv6, Raw, TCP, UDP
    src = dst = ''
    lastlayer = packet.lastlayer() if hasattr(packet, 'lastlayer') else None
    protocol = lastlayer.name.upper() if lastlayer else 'UNKNOWN'
    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst; protocol = str(packet[IP].proto)
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    elif Ether in packet:
        src, dst = packet[Ether].src, packet[Ether].dst
    sport = dport = None; flags = ''
    if TCP in packet:
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport); protocol = 'TCP'; flags = str(packet[TCP].flags)
    elif UDP in packet:
        sport, dport = int(packet[UDP].sport), int(packet[UDP].dport); protocol = 'UDP'
    elif ICMP in packet:
        protocol = 'ICMP'
    dns_query = ''; dns_is_response = False; dns_rcode = ''
    if DNS in packet:
        layer = packet[DNS]; dns_is_response = bool(getattr(layer, 'qr', 0))
        if dns_is_response:
            dns_rcode = str(int(getattr(layer, 'rcode', 0)))
        if getattr(layer, 'qd', None) and DNSQR in packet:
            dns_query = _text(packet[DNSQR].qname)
        protocol = 'DNS'
    http_host = http_uri = ''
    if Raw in packet and (sport in {80,8080} or dport in {80,8080}):
        try:
            header = bytes(packet[Raw].load).decode('latin-1','ignore')
            for line in header.split('\r\n'):
                if line.lower().startswith('host:'):
                    http_host = line.split(':',1)[1].strip()
                if line.startswith(('GET ','POST ','PUT ','DELETE ','HEAD ')):
                    parts = line.split(); http_uri = parts[1] if len(parts) > 1 else ''
        except Exception:
            pass
    return PacketRecord(number=number,timestamp=float(getattr(packet,'time',0.0) or 0.0),length=len(packet),src=src,dst=dst,
        protocol=protocol,src_port=sport,dst_port=dport,dns_query=dns_query,dns_is_response=dns_is_response,dns_rcode=dns_rcode,
        http_host=http_host,http_uri=http_uri,tcp_flags=flags)


class ScapyBackend(CaptureBackend):
    def available(self) -> bool:
        try:
            import scapy.all  # noqa: F401
            return True
        except Exception:
            return False

    def read(self, path: Path, *, tls_keylog: Path | None = None) -> Iterable[PacketRecord]:
        del tls_keylog
        from scapy.all import PcapReader
        with PcapReader(str(path)) as reader:
            for number, packet in enumerate(reader, 1):
                yield packet_to_record(packet, number)
