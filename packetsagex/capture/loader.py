from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
from typing import Iterable

from .scapy_backend import ScapyBackend
from .tshark import TsharkBackend
from ..models import PacketRecord


class CaptureError(RuntimeError):
    pass


def _validated_stream(
    name: str,
    stream: Iterable[PacketRecord],
) -> Iterable[PacketRecord]:
    """Yield records while converting backend read failures into CaptureError.

    Capture backends are lazy iterators, so failures such as a TShark permission
    error may happen only after iteration starts. Wrapping the iterator here lets
    auto mode fall back cleanly when a backend cannot actually read a capture.
    """
    try:
        yield from stream
    except Exception as exc:
        raise CaptureError(f"{name} backend failed: {exc}") from exc


def _looks_like_permission_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "permission denied" in text
        or "don't have permission" in text
        or "do not have permission" in text
        or "not permitted" in text
    )


def _staged_tshark_stream(
    backend: TsharkBackend,
    capture: Path,
    keylog: Path | None,
) -> Iterable[PacketRecord]:
    """Retry TShark from a private temporary path without weakening OS security.

    Some Linux security profiles permit TShark to read /tmp while denying direct
    access to the same user-readable capture elsewhere. The temporary directory
    is private to the current user and is removed automatically after iteration.
    """
    with tempfile.TemporaryDirectory(prefix="packetsagex-tshark-") as temp_dir:
        temp_root = Path(temp_dir)
        staged_capture = temp_root / f"capture{capture.suffix.lower()}"
        shutil.copyfile(capture, staged_capture)
        os.chmod(staged_capture, 0o600)

        staged_keylog: Path | None = None
        if keylog is not None:
            staged_keylog = temp_root / "tls-keylog.log"
            shutil.copyfile(keylog, staged_keylog)
            os.chmod(staged_keylog, 0o600)

        yield from backend.read(staged_capture, tls_keylog=staged_keylog)


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

    errors: list[str] = []
    for name, candidate in candidates:
        if not candidate.available():
            continue

        try:
            stream = candidate.read(capture, tls_keylog=keylog)
            iterator = iter(stream)
            first = next(iterator, None)
        except Exception as exc:
            if name == "tshark" and _looks_like_permission_error(exc):
                try:
                    staged_stream = _staged_tshark_stream(candidate, capture, keylog)
                    iterator = iter(staged_stream)
                    first = next(iterator, None)
                except Exception as staged_exc:
                    errors.append(f"{name}: {exc}; staged retry: {staged_exc}")
                    if backend != "auto":
                        raise CaptureError(
                            f"{name} backend failed: {exc}; staged retry failed: {staged_exc}"
                        ) from staged_exc
                    continue
            else:
                errors.append(f"{name}: {exc}")
                if backend != "auto":
                    raise CaptureError(f"{name} backend failed: {exc}") from exc
                continue

        def records(
            first_record: PacketRecord | None = first,
            remaining: Iterable[PacketRecord] = iterator,
            backend_name: str = name,
        ) -> Iterable[PacketRecord]:
            if first_record is not None:
                yield first_record
            yield from _validated_stream(backend_name, remaining)

        return name, records()

    detail = f" Backend errors: {'; '.join(errors)}" if errors else ""
    raise CaptureError(
        "No capture backend could read the capture. Install Wireshark/TShark "
        "(recommended) or install PacketSageX with Scapy support." + detail
    )
