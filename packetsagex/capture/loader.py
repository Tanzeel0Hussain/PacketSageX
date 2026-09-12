from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .scapy_backend import ScapyBackend
from .tshark import TsharkBackend
from ..models import PacketRecord


class CaptureError(RuntimeError):
    pass


def load_packets(
    path: str | Path,
    *,
    backend: str = "auto",
    tls_keylog: str | Path | None = None,
) -> tuple[str, Iterable[PacketRecord]]:
    capture = Path(path).expanduser().resolve()
    if not capture.exists():
        raise CaptureError(f"Capture file not found: {capture}")
    if capture.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise CaptureError("Expected a .pcap, .pcapng, or .cap capture file")

    keylog = Path(tls_keylog).expanduser().resolve() if tls_keylog else None
    if keylog and not keylog.exists():
        raise CaptureError(f"TLS key log not found: {keylog}")

    candidates = [("tshark", TsharkBackend()), ("scapy", ScapyBackend())]
    if backend != "auto":
        candidates = [item for item in candidates if item[0] == backend]
        if not candidates:
            raise CaptureError(f"Unknown backend: {backend}")

    for name, candidate in candidates:
        if candidate.available():
            return name, candidate.read(capture, tls_keylog=keylog)

    raise CaptureError(
        "No capture backend is available. Install Wireshark/TShark (recommended) "
        "or install PacketSageX with Scapy support."
    )
