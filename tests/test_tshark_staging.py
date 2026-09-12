from pathlib import Path

from packetsagex.capture import loader
from packetsagex.models import PacketRecord


class _DeniedThenStagedTshark:
    staged_path: Path | None = None

    def available(self) -> bool:
        return True

    def read(self, path: Path, *, tls_keylog: Path | None = None):
        del tls_keylog
        if "packetsagex-tshark-" not in str(path.parent):
            raise RuntimeError(f'tshark: You don\'t have permission to read the file "{path}".')
        type(self).staged_path = path
        yield PacketRecord(1, 1.0, 64, "10.0.0.1", "1.1.1.1", "TCP", 50000, 443)


class _UnavailableScapy:
    def available(self) -> bool:
        return False


def test_tshark_permission_error_retries_from_secure_temp(monkeypatch, tmp_path):
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"pcap-test")

    monkeypatch.setattr(loader, "TsharkBackend", _DeniedThenStagedTshark)
    monkeypatch.setattr(loader, "ScapyBackend", _UnavailableScapy)

    backend, records = loader.load_packets(capture, backend="tshark")
    result = list(records)

    assert backend == "tshark"
    assert len(result) == 1
    assert result[0].dst == "1.1.1.1"
    assert _DeniedThenStagedTshark.staged_path is not None
    assert "packetsagex-tshark-" in str(_DeniedThenStagedTshark.staged_path.parent)
    assert not _DeniedThenStagedTshark.staged_path.exists()
