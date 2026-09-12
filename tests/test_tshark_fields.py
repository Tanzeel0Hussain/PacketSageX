from __future__ import annotations

import io
from pathlib import Path

from packetsagex.capture import tshark


class _FakeProcess:
    def __init__(self, output: str) -> None:
        self.stdout = io.StringIO(output)
        self.stderr = io.StringIO("")

    def wait(self) -> int:
        return 0


def test_tshark_uses_native_tab_separator_and_parses_rows(monkeypatch, tmp_path):
    row = [
        "1", "1.25", "120", "", "", "10.0.0.2", "", "1.1.1.1", "", "TLS",
        "50000", "", "443", "", "", "0", "", "example.com", "0x0304", "", "", "", "0x0018",
    ]
    output = "\t".join(f'"{value}"' for value in row) + "\n"
    seen: dict[str, list[str]] = {}

    def fake_popen(cmd, **kwargs):
        del kwargs
        seen["cmd"] = list(cmd)
        return _FakeProcess(output)

    monkeypatch.setattr(tshark.subprocess, "Popen", fake_popen)

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"test")
    records = list(tshark.TsharkBackend().read(Path(capture)))

    assert len(records) == 1
    assert records[0].src == "10.0.0.2"
    assert records[0].dst == "1.1.1.1"
    assert records[0].protocol == "TLS"
    assert records[0].server_name == "example.com"
    assert records[0].tls_version == "0x0304"
    assert not any(str(part).startswith("separator=") for part in seen["cmd"])
