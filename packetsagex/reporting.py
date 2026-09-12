from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return target


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
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
    target.parent.mkdir(parents=True, exist_ok=True)
    flows = report.get("flows", [])
    findings = report.get("security_findings", [])

    rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(flow.get('src','')))}</td>"
        f"<td>{html.escape(str(flow.get('dst','')))}</td>"
        f"<td>{html.escape(str(flow.get('protocol','')))}</td>"
        f"<td>{int(flow.get('packets',0) or 0)}</td>"
        f"<td>{int(flow.get('bytes',0) or 0)}</td>"
        f"<td>{html.escape(str(flow.get('classification','')))}</td>"
        f"<td>{int(flow.get('confidence',0) or 0)}%</td>"
        "</tr>"
        for flow in flows
    )

    finding_html = "".join(
        f"<li><strong>{html.escape(str(item.get('severity',''))).upper()}</strong> — "
        f"{html.escape(str(item.get('title','')))}: {html.escape(str(item.get('evidence','')))}</li>"
        for item in findings
    ) or "<li>No heuristic findings triggered.</li>"

    source = html.escape(str(report.get("source", "")))
    packets = int(report.get("packet_count", 0) or 0)
    flows_count = int(report.get("flow_count", 0) or 0)
    byte_count = int(report.get("byte_count", 0) or 0)
    backend = html.escape(str(report.get("backend", "n/a")))
    interface = html.escape(str(report.get("interface", "n/a")))

    document = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PacketSageX Report</title>
<style>
:root {
  color-scheme: dark;
  --bg:#07101d; --panel:#0d1b2d; --panel2:#111f34; --line:#253650;
  --text:#e8f0fb; --muted:#9db0c9; --accent:#58d7ff; --accent2:#7fffc2;
}
* { box-sizing:border-box; }
body { margin:0; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:var(--bg); color:var(--text); }
main { max-width:1500px; margin:0 auto; padding:28px; }
h1 { margin:0 0 8px; letter-spacing:-.03em; }
h2 { margin-top:28px; }
.sub { color:var(--muted); word-break:break-all; }
.grid { display:grid; grid-template-columns:repeat(5,minmax(150px,1fr)); gap:12px; margin:20px 0; }
.card { background:linear-gradient(145deg,var(--panel),var(--panel2)); border:1px solid var(--line); padding:16px; border-radius:14px; }
.metric { font-size:1.45rem; font-weight:700; margin-top:5px; }
.label { color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.08em; }
.controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; padding:14px; background:var(--panel); border:1px solid var(--line); border-radius:14px; position:sticky; top:0; z-index:3; }
input, select, button { background:#081522; color:var(--text); border:1px solid #31445f; border-radius:9px; padding:10px 12px; font:inherit; }
input { flex:1 1 420px; min-width:250px; }
button { cursor:pointer; }
button.active { border-color:var(--accent); color:var(--accent); box-shadow:0 0 0 1px rgba(88,215,255,.22) inset; }
.table-wrap { overflow:auto; border:1px solid var(--line); border-radius:14px; margin-top:12px; }
table { border-collapse:collapse; width:100%; min-width:980px; background:#091522; }
th, td { padding:11px 12px; border-bottom:1px solid #1d2d45; text-align:left; white-space:nowrap; }
th { position:sticky; top:0; background:#102039; color:#cfe8ff; z-index:2; }
tbody tr:hover { background:#0f2239; }
.badge { display:inline-block; padding:3px 8px; border-radius:999px; background:#102942; color:var(--accent2); }
.muted { color:var(--muted); }
#resultCount { margin-left:auto; color:var(--muted); }
ul { line-height:1.65; }
@media (max-width:900px) { .grid { grid-template-columns:repeat(2,1fr); } main { padding:16px; } #resultCount { width:100%; margin-left:0; } }
</style>
</head>
<body>
<main>
  <h1>PacketSageX Analysis Report</h1>
  <div class="sub">__SOURCE__</div>

  <section class="grid">
    <div class="card"><div class="label">Packets</div><div class="metric">__PACKETS__</div></div>
    <div class="card"><div class="label">Flows</div><div class="metric">__FLOWS__</div></div>
    <div class="card"><div class="label">Bytes</div><div class="metric">__BYTES__</div></div>
    <div class="card"><div class="label">Backend</div><div class="metric">__BACKEND__</div></div>
    <div class="card"><div class="label">Interface</div><div class="metric">__INTERFACE__</div></div>
  </section>

  <h2>Security Findings</h2>
  <div class="card"><ul>__FINDINGS__</ul></div>

  <h2>Flows</h2>
  <div class="controls">
    <input id="searchBox" type="search" autocomplete="off" placeholder="Search Source, Destination, Protocol, Packets, Bytes, Likely Traffic, Confidence">
    <select id="sortField" aria-label="Sort field">
      <option value="bytes">Sort by Bytes</option>
      <option value="packets">Sort by Packets</option>
      <option value="confidence">Sort by Confidence</option>
      <option value="source">Sort by Source</option>
      <option value="destination">Sort by Destination</option>
      <option value="protocol">Sort by Protocol</option>
      <option value="traffic">Sort by Likely Traffic</option>
    </select>
    <button id="topBtn" class="active" type="button">Top ↓</button>
    <button id="bottomBtn" type="button">Bottom ↑</button>
    <span id="resultCount"></span>
  </div>

  <div class="table-wrap">
    <table id="flowTable">
      <thead>
        <tr>
          <th>Source</th>
          <th>Destination</th>
          <th>Protocol</th>
          <th>Packets</th>
          <th>Bytes</th>
          <th>Likely Traffic</th>
          <th>Confidence</th>
        </tr>
      </thead>
      <tbody>__ROWS__</tbody>
    </table>
  </div>

  <p class="muted">Search checks every visible flow field. “Top” sorts highest/largest values first; “Bottom” reverses the order. Classification is evidence-based and may be uncertain for encrypted or shared infrastructure.</p>
</main>

<script>
(() => {
  const tbody = document.querySelector("#flowTable tbody");
  const originalRows = Array.from(tbody.querySelectorAll("tr"));
  const search = document.getElementById("searchBox");
  const sortField = document.getElementById("sortField");
  const topBtn = document.getElementById("topBtn");
  const bottomBtn = document.getElementById("bottomBtn");
  const resultCount = document.getElementById("resultCount");
  let direction = "top";

  const index = {
    source:0, destination:1, protocol:2, packets:3, bytes:4, traffic:5, confidence:6
  };
  const numeric = new Set(["packets","bytes","confidence"]);

  function cellValue(row, field) {
    const text = row.children[index[field]].textContent.trim();
    if (numeric.has(field)) return Number(text.replace(/[^0-9.-]/g, "")) || 0;
    return text.toLowerCase();
  }

  function render() {
    const query = search.value.trim().toLowerCase();
    const field = sortField.value;

    const rows = originalRows.filter(row => {
      if (!query) return true;
      return Array.from(row.children).some(cell =>
        cell.textContent.toLowerCase().includes(query)
      );
    });

    rows.sort((a, b) => {
      const av = cellValue(a, field);
      const bv = cellValue(b, field);
      let result;
      if (numeric.has(field)) result = av - bv;
      else result = String(av).localeCompare(String(bv));
      return direction === "top" ? -result : result;
    });

    tbody.replaceChildren(...rows);
    resultCount.textContent = `${rows.length.toLocaleString()} of ${originalRows.length.toLocaleString()} flows`;
  }

  search.addEventListener("input", render);
  sortField.addEventListener("change", render);

  topBtn.addEventListener("click", () => {
    direction = "top";
    topBtn.classList.add("active");
    bottomBtn.classList.remove("active");
    render();
  });

  bottomBtn.addEventListener("click", () => {
    direction = "bottom";
    bottomBtn.classList.add("active");
    topBtn.classList.remove("active");
    render();
  });

  render();
})();
</script>
</body>
</html>
"""
    replacements = {
        "__SOURCE__": source,
        "__PACKETS__": f"{packets:,}",
        "__FLOWS__": f"{flows_count:,}",
        "__BYTES__": f"{byte_count:,}",
        "__BACKEND__": backend,
        "__INTERFACE__": interface,
        "__FINDINGS__": finding_html,
        "__ROWS__": rows,
    }
    for key, value in replacements.items():
        document = document.replace(key, value)

    target.write_text(document, encoding="utf-8")
    return target
