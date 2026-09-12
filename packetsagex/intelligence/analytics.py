from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import ipaddress

from ..models import PacketRecord


_DNS_RCODE_NAMES = {"0":"NOERROR","1":"FORMERR","2":"SERVFAIL","3":"NXDOMAIN","4":"NOTIMP","5":"REFUSED"}


@dataclass(slots=True)
class _EndpointState:
    sent_packets: int = 0
    received_packets: int = 0
    sent_bytes: int = 0
    received_bytes: int = 0
    protocols: Counter[str] = field(default_factory=Counter)
    peers: set[str] = field(default_factory=set)


class NetworkIntelligence:
    """Streaming-safe endpoint, DNS, TLS and QUIC analytics."""

    def __init__(self) -> None:
        self.endpoints: dict[str, _EndpointState] = {}
        self.dns_queries: Counter[str] = Counter()
        self.dns_clients: Counter[str] = Counter()
        self.dns_rcodes: Counter[str] = Counter()
        self.dns_query_packets = 0
        self.dns_response_packets = 0
        self.tls_packets = 0
        self.tls_server_names: Counter[str] = Counter()
        self.tls_versions: Counter[str] = Counter()
        self.quic_packets = 0
        self.quic_versions: Counter[str] = Counter()

    def add(self, packet: PacketRecord) -> None:
        if packet.src:
            state = self.endpoints.setdefault(packet.src, _EndpointState())
            state.sent_packets += 1
            state.sent_bytes += packet.length
            state.protocols[packet.protocol] += 1
            if packet.dst:
                state.peers.add(packet.dst)
        if packet.dst:
            state = self.endpoints.setdefault(packet.dst, _EndpointState())
            state.received_packets += 1
            state.received_bytes += packet.length
            state.protocols[packet.protocol] += 1
            if packet.src:
                state.peers.add(packet.src)

        if packet.dns_query:
            query = packet.dns_query.rstrip('.').lower()
            if packet.dns_is_response:
                self.dns_response_packets += 1
            else:
                self.dns_query_packets += 1
                self.dns_queries[query] += 1
                if packet.src:
                    self.dns_clients[packet.src] += 1
        elif packet.dns_is_response:
            self.dns_response_packets += 1

        if packet.dns_is_response and packet.dns_rcode:
            code = str(packet.dns_rcode)
            self.dns_rcodes[_DNS_RCODE_NAMES.get(code, code)] += 1

        protocol = packet.protocol.upper()
        if 'TLS' in protocol or packet.server_name or packet.tls_version:
            self.tls_packets += 1
        if packet.server_name:
            self.tls_server_names[packet.server_name.lower()] += 1
        if packet.tls_version:
            self.tls_versions[packet.tls_version] += 1
        if 'QUIC' in protocol or packet.quic_version:
            self.quic_packets += 1
        if packet.quic_version:
            self.quic_versions[packet.quic_version] += 1

    @staticmethod
    def _scope(address: str) -> str:
        if address == '255.255.255.255':
            return 'broadcast'
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return 'link-layer/other'
        if ip.is_multicast:
            return 'multicast'
        if ip.is_loopback:
            return 'loopback'
        if ip.is_link_local:
            return 'link-local'
        if ip.is_private:
            return 'private/local'
        if ip.is_global:
            return 'public'
        return 'special'

    @staticmethod
    def _activity(state: _EndpointState) -> str:
        total = state.sent_packets + state.received_packets
        if total == 0:
            return 'unknown'
        sent_ratio = state.sent_packets / total
        if sent_ratio >= 0.7:
            return 'mostly-sender'
        if sent_ratio <= 0.3:
            return 'mostly-receiver'
        return 'bidirectional'

    def endpoint_inventory(self, limit: int = 100) -> list[dict[str, object]]:
        rows = []
        for endpoint, state in self.endpoints.items():
            rows.append({
                'endpoint': endpoint,
                'scope': self._scope(endpoint),
                'activity': self._activity(state),
                'packets': state.sent_packets + state.received_packets,
                'bytes': state.sent_bytes + state.received_bytes,
                'sent_packets': state.sent_packets,
                'received_packets': state.received_packets,
                'sent_bytes': state.sent_bytes,
                'received_bytes': state.received_bytes,
                'peer_count': len(state.peers),
                'protocols': [name for name, _ in state.protocols.most_common(6)],
            })
        rows.sort(key=lambda item: (int(item['bytes']), int(item['packets'])), reverse=True)
        return rows[:limit]

    def dns_analytics(self) -> dict[str, object]:
        return {
            'query_packets': self.dns_query_packets,
            'response_packets': self.dns_response_packets,
            'unique_queries': len(self.dns_queries),
            'top_queries': [{'query': name, 'count': count} for name, count in self.dns_queries.most_common(25)],
            'top_clients': [{'client': name, 'count': count} for name, count in self.dns_clients.most_common(15)],
            'response_codes': dict(self.dns_rcodes.most_common()),
            'nxdomain_count': self.dns_rcodes.get('NXDOMAIN', 0),
        }

    def tls_quic_intelligence(self) -> dict[str, object]:
        return {
            'tls_packets': self.tls_packets,
            'quic_packets': self.quic_packets,
            'unique_server_names': len(self.tls_server_names),
            'top_server_names': [{'server_name': name, 'count': count} for name, count in self.tls_server_names.most_common(25)],
            'tls_versions': dict(self.tls_versions.most_common()),
            'quic_versions': dict(self.quic_versions.most_common()),
        }
