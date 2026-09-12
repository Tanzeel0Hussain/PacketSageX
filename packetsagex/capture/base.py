from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from ..models import PacketRecord


class CaptureBackend(ABC):
    @abstractmethod
    def available(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def read(self, path: Path, *, tls_keylog: Path | None = None) -> Iterable[PacketRecord]:
        raise NotImplementedError
