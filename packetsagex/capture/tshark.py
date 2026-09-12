from __future__ import annotations

import csv
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from .base import CaptureBackend
from ..models import PacketRecord


FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "_ws.col.Protocol",
    "tcp.srcport",
    "udp.srcport",
    "tcp.dstport",
    "udp.dstport",
    "dns.qry.name",
    "dns.flags.response",
    "dns.flags.rcode",
    "tls.handshake.extensions_server_name",
    "tls.handshake.version",
    "quic.version",
    "http.host",
    "http.request.uri",
    "tcp.flags.str",
]


def _first(*values: str) -> str:
    return next((value for value in values if value), "")


def _int(value: str) -> int | None:
    try:
        return int(value.split(",", 1)[0]) if value else None
    except ValueError:
        return None


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


class TsharkBackend(CaptureBackend):
    def available(self) -> bool:
        return shutil.which("tshark") is not None

    def read(self, path: Path, *, tls_keylog: Path | None = None) -> Iterable[PacketRecord]:
        # TShark's fields output uses a tab separator by default. Do not pass the
        # literal string "\\t" to -E separator: some TShark builds interpret it
        # as ordinary characters, which makes every row look like one CSV field
        # and can silently produce a zero-packet PacketSageX report.
        cmd = [
            "tshark",
            "-n",
            "-r",
            str(path),
            "-T",
            "fields",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        if tls_keylog:
            cmd.extend(["-o", f"tls.keylog_file:{tls_keylog}"])
        for field in FIELDS:
            cmd.extend(["-e", field])

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert proc.stdout is not None
        reader = csv.reader(proc.stdout, delimiter="\t", quotechar='"')
        try:
            for row in reader:
                row += [""] * (len(FIELDS) - len(row))
                try:
                    number = int(row[0] or 0)
                    timestamp = float(row[1] or 0)
                    length = int(row[2] or 0)
                except ValueError:
                    continue

                yield PacketRecord(
                    number=number,
                    timestamp=timestamp,
                    length=length,
                    src=_first(row[5], row[6], row[3]),
                    dst=_first(row[7], row[8], row[4]),
                    protocol=(row[9] or "UNKNOWN").upper(),
                    src_port=_int(_first(row[10], row[11])),
                    dst_port=_int(_first(row[12], row[13])),
                    dns_query=row[14],
                    dns_is_response=_bool(row[15]),
                    dns_rcode=row[16],
                    server_name=row[17],
                    tls_version=row[18],
                    quic_version=row[19],
                    http_host=row[20],
                    http_uri=row[21],
                    tcp_flags=row[22],
                )
        finally:
            stderr = proc.stderr.read() if proc.stderr else ""
            code = proc.wait()
            if code != 0:
                raise RuntimeError(stderr.strip() or f"tshark exited with code {code}")
