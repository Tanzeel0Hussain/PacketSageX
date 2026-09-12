from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "src", "dst", "protocol", "src_port", "dst_port", "packets", "bytes",
            "duration", "classification", "confidence", "evidence",
        ])
        writer.writeheader()
        for flow in report.get("flows", []):
            row = {key: flow.get(key, "") for key in writer.fieldnames}
            if isinstance(row["evidence"], list):
                row["evidence"] = "; ".join(row["evidence"])
            writer.writerow(row)
    return target


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    flows = report.get("flows", [])[:100]
    findings = report.get("security_findings", [])
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(flow.get('src','')))}</td>"
        f"<td>{html.escape(str(flow.get('dst','')))}</td>"
        f"<td>{html.escape(str(flow.get('protocol','')))}</td>"
        f"<td>{flow.get('packets',0)}</td><td>{flow.get('bytes',0)}</td>"
        f"<td>{html.escape(str(flow.get('classification','')))}</td>"
        f"<td>{flow.get('confidence',0)}%</td>"
        "</tr>" for flow in flows
    )
    finding_html = "".join(
        f"<li><strong>{html.escape(str(item.get('severity',''))).upper()}</strong> — "
        f"{html.escape(str(item.get('title','')))}: {html.escape(str(item.get('evidence','')))}</li>"
        for item in findings
    ) or "<li>No heuristic findings triggered.</li>"
    document = f"""<!doctype html><html><head><meta charset='utf-8'><title>PacketSageX Report</title>
<style>body{{font-family:system-ui;background:#08111f;color:#e6edf7;margin:32px}}table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border-bottom:1px solid #24324a;text-align:left}}.card{{background:#0e1b2f;padding:18px;border-radius:12px;margin:16px 0}}code{{color:#68e1ff}}</style></head><body>
<h1>PacketSageX Analysis Report</h1><p>{html.escape(str(report.get('source','')))}</p>
<div class='card'><b>Packets:</b> {report.get('packet_count',0)} &nbsp; <b>Flows:</b> {report.get('flow_count',0)} &nbsp; <b>Bytes:</b> {report.get('byte_count',0)}</div>
<h2>Security Findings</h2><ul>{finding_html}</ul><h2>Top Flows</h2>
<table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Likely Traffic</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table>
<p>Classification is evidence-based and may be uncertain for encrypted/shared infrastructure.</p></body></html>"""
    target.write_text(document, encoding="utf-8")
    return target
