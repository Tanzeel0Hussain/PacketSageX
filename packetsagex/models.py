from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class PacketRecord:
    number: int
    timestamp: float
    length: int
    src: str = ""
    dst: str = ""
    protocol: str = "UNKNOWN"
    src_port: int | None = None
    dst_port: int | None = None
    dns_query: str = ""
    dns_is_response: bool = False
    dns_rcode: str = ""
    server_name: str = ""
    tls_version: str = ""
    quic_version: str = ""
    http_host: str = ""
    http_uri: str = ""
    tcp_flags: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FlowSummary:
    key: str
    src: str
    dst: str
    protocol: str
    src_port: int | None
    dst_port: int | None
    packets: int = 0
    bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    classification: str = "Unknown"
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["duration"] = round(self.duration, 6)
        return data
