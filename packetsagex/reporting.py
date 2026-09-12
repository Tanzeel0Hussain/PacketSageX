from __future__ import annotations

import csv
from datetime import datetime
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
    fields = [
        "src",
        "dst",
        "protocol",
        "src_port",
        "dst_port",
        "packets",
        "bytes",
        "duration",
        "classification",
        "confidence",
        "evidence",
    ]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for flow in report.get("flows", []):
            row = {key: flow.get(key, "") for key in fields}
            if isinstance(row["evidence"], list):
                row["evidence"] = "; ".join(row["evidence"])
            writer.writerow(row)
    return target


def _td(value: object) -> str:
    return f"<td>{html.escape(str(value))}</td>"


def _rows_or_empty(rows: str, columns: int, message: str) -> str:
    return rows or f'<tr><td colspan="{columns}" class="empty">{html.escape(message)}</td></tr>'


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    flows = report.get("flows", []) or []
    findings = report.get("security_findings", []) or []
    inventory = report.get("endpoint_inventory", []) or []
    dns = report.get("dns_analytics", {}) or {}
    encrypted = report.get("tls_quic_intelligence", {}) or {}
    categories = report.get("traffic_categories", {}) or {}

    flow_rows = "".join(
        "<tr>"
        + "".join(
            [
                _td(flow.get("src", "")),
                _td(flow.get("dst", "")),
                _td(flow.get("protocol", "")),
                _td(int(flow.get("packets", 0) or 0)),
                _td(int(flow.get("bytes", 0) or 0)),
                _td(flow.get("classification", "")),
                _td(f"{int(flow.get('confidence', 0) or 0)}%"),
            ]
        )
        + "</tr>"
        for flow in flows
    )
    flow_rows = _rows_or_empty(flow_rows, 7, "No flows were recorded.")

    endpoint_rows = "".join(
        "<tr>"
        + "".join(
            [
                _td(item.get("endpoint", "")),
                _td(item.get("scope", "")),
                _td(item.get("activity", "")),
                _td(item.get("packets", 0)),
                _td(item.get("bytes", 0)),
                _td(item.get("peer_count", 0)),
                _td(", ".join(item.get("protocols", []))),
            ]
        )
        + "</tr>"
        for item in inventory[:100]
    )
    endpoint_rows = _rows_or_empty(endpoint_rows, 7, "No endpoint data.")

    dns_rows = "".join(
        "<tr>" + _td(item.get("query", "")) + _td(item.get("count", 0)) + "</tr>"
        for item in dns.get("top_queries", [])[:50]
    )
    dns_rows = _rows_or_empty(dns_rows, 2, "No DNS queries observed.")

    sni_rows = "".join(
        "<tr>"
        + _td(item.get("server_name", ""))
        + _td(item.get("count", 0))
        + "</tr>"
        for item in encrypted.get("top_server_names", [])[:50]
    )
    sni_rows = _rows_or_empty(sni_rows, 2, "No visible TLS SNI observed.")

    category_rows = "".join(
        "<tr>" + _td(name) + _td(count) + "</tr>"
        for name, count in sorted(categories.items(), key=lambda item: item[1], reverse=True)
    )
    category_rows = _rows_or_empty(category_rows, 2, "No traffic categories available.")

    finding_html = "".join(
        "<article class=\"finding\">"
        f"<span class=\"severity {html.escape(str(item.get('severity', 'info')).lower())}\">"
        f"{html.escape(str(item.get('severity', 'info')).upper())}</span>"
        f"<h3>{html.escape(str(item.get('title', 'Finding')))}</h3>"
        f"<p>{html.escape(str(item.get('evidence', '')))}</p>"
        "</article>"
        for item in findings
    ) or '<div class="empty-state">No heuristic security findings triggered.</div>'

    source = html.escape(str(report.get("source", "")))
    backend = html.escape(str(report.get("backend", "n/a")))
    interface = html.escape(str(report.get("interface", "n/a")))
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    document = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PacketSageX Analysis Report</title>
<style>
:root{color-scheme:dark;--bg:#050b12;--panel:#0a1522;--panel2:#0e1d2d;--line:#1c3850;--text:#ecf7ff;--muted:#8faabe;--cyan:#43e5ff;--green:#4cff9b;--amber:#ffd166;--red:#ff6b7a;--shadow:0 18px 60px rgba(0,0,0,.28)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at top right,#0b2a3d 0,#050b12 34rem);color:var(--text)}button,input,select{font:inherit}main{max-width:1580px;margin:auto;padding:0 26px 36px}.topbar{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;gap:18px;align-items:center;padding:18px 26px;background:rgba(5,11,18,.93);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}.brand{display:flex;gap:14px;align-items:center}.mark{width:48px;height:48px;border:1px solid var(--cyan);border-radius:12px;display:grid;place-items:center;color:var(--cyan);font-weight:900;box-shadow:0 0 26px rgba(67,229,255,.18)}.brand h1{font-size:1.08rem;letter-spacing:.09em;margin:0}.brand small{display:block;margin-top:3px;color:var(--muted)}.actions{display:flex;gap:10px}.action{cursor:pointer;background:linear-gradient(180deg,#123047,#0a1d2b);border:1px solid #2e607b;color:var(--text);border-radius:10px;padding:10px 14px;font-weight:700}.action:hover{border-color:var(--cyan);color:var(--cyan)}.hero{padding:28px 0 18px}.eyebrow{color:var(--green);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;letter-spacing:.12em}.hero h2{font-size:clamp(1.65rem,3vw,2.5rem);margin:8px 0}.meta{display:flex;flex-wrap:wrap;gap:8px;color:var(--muted)}.pill{border:1px solid var(--line);background:#08131e;border-radius:999px;padding:7px 10px}.tabs{position:sticky;top:85px;z-index:15;display:flex;gap:8px;overflow:auto;padding:10px;background:rgba(8,19,30,.96);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.tab-btn{cursor:pointer;white-space:nowrap;border:1px solid transparent;background:transparent;color:var(--muted);border-radius:9px;padding:10px 13px;font-weight:800}.tab-btn:hover{color:var(--text);background:#0d2030}.tab-btn.active{color:#031017;background:var(--cyan);border-color:var(--cyan)}.tab-panel{display:none;padding-top:20px}.tab-panel.active{display:block}.section-title{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:8px 0 14px}.section-title h2{margin:0;font-size:1.25rem}.section-title p{margin:0;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:0 0 18px}.card,.panel{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.card{padding:17px}.metric{font-size:1.55rem;font-weight:850;margin-top:4px}.label{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.08em}.panel{padding:18px;margin-bottom:16px}.panel h3{margin:0 0 12px;font-size:1rem}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:#07111c}table{border-collapse:collapse;width:100%;min-width:850px}th,td{padding:10px 12px;border-bottom:1px solid #162c40;text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#0e2234;color:#caecff;font-size:.8rem;letter-spacing:.03em}tbody tr:hover{background:#0b1d2c}.empty{color:var(--muted);text-align:center;padding:25px}.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}.controls input,.controls select,.controls button{background:#07131f;color:var(--text);border:1px solid #2a455c;border-radius:9px;padding:10px 12px}.controls input{flex:1 1 420px}.controls button{cursor:pointer}.controls button.active{border-color:var(--cyan);color:var(--cyan)}#resultCount{margin-left:auto;color:var(--muted)}.finding{border:1px solid var(--line);border-left:4px solid var(--amber);border-radius:12px;padding:15px;margin-bottom:10px;background:#091622}.finding h3{display:inline;margin:0 0 0 10px}.finding p{margin:10px 0 0;color:#c4d6e4}.severity{display:inline-block;padding:4px 8px;border-radius:999px;font-size:.7rem;font-weight:900;letter-spacing:.06em;background:#22364a}.severity.high,.severity.critical{color:#fff;background:#8b2330}.severity.medium{color:#1f1600;background:var(--amber)}.severity.low,.severity.info{color:#002816;background:var(--green)}.empty-state{padding:26px;text-align:center;color:var(--muted);border:1px dashed #29445a;border-radius:12px}.note{color:var(--muted);line-height:1.65}.print-only{display:none}.footer{padding:24px 0 6px;color:var(--muted);text-align:center;font-size:.82rem}
@media(max-width:760px){main{padding:0 14px 24px}.topbar{padding:14px}.brand small{display:none}.actions .action{padding:9px}.tabs{top:76px}.hero{padding-top:20px}.section-title{display:block}.section-title p{margin-top:5px}}
@media print{@page{size:A4 landscape;margin:10mm}:root{color-scheme:light;--bg:#fff;--panel:#fff;--panel2:#fff;--line:#b8c1c9;--text:#111827;--muted:#4b5563;--cyan:#006b7a;--green:#08783d;--shadow:none}body{background:#fff;color:#111827;font-size:9.5pt}.topbar{position:static;padding:0 0 10px;background:#fff;border-bottom:2px solid #111827}.actions,.tabs,.controls,.footer{display:none!important}.mark{box-shadow:none;color:#006b7a;border-color:#006b7a}.hero{padding:12px 0}.hero h2{font-size:18pt}.tab-panel{display:block!important;padding-top:8px;page-break-before:auto}.tab-panel+.tab-panel{page-break-before:always}.card,.panel{box-shadow:none;background:#fff;border-color:#c6ccd2}.grid{grid-template-columns:repeat(5,1fr);gap:6px}.card{padding:8px}.metric{font-size:13pt}.table-wrap{overflow:visible;border-color:#c6ccd2}table{min-width:0;font-size:8pt;page-break-inside:auto}thead{display:table-header-group}tr{page-break-inside:avoid;page-break-after:auto}th,td{white-space:normal;padding:5px 6px;border-color:#d8dde2}th{position:static;background:#edf2f6;color:#111827}.finding{background:#fff;break-inside:avoid}.print-only{display:block}.screen-only{display:none!important}.note{color:#374151}.section-title{margin-top:0}.section-title h2{font-size:14pt}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand"><div class="mark">PSX</div><div><h1>PACKETSAGEX</h1><small>Network Traffic Intelligence &amp; Forensics Platform</small></div></div>
  <div class="actions"><button id="printBtn" class="action" type="button">Print / Save PDF</button></div>
</header>
<main>
  <section class="hero">
    <div class="eyebrow">DEFENSIVE NETWORK FORENSICS REPORT</div>
    <h2>PacketSageX Analysis Report</h2>
    <div class="meta">
      <span class="pill">Source: __SOURCE__</span>
      <span class="pill">Backend: __BACKEND__</span>
      <span class="pill">Interface: __INTERFACE__</span>
      <span class="pill">Generated: __GENERATED__</span>
    </div>
    <p class="print-only">This print view expands every report tab so the exported PDF contains the complete analysis.</p>
  </section>

  <nav class="tabs" aria-label="Report sections">
    <button class="tab-btn active" type="button" data-tab="overview">Overview</button>
    <button class="tab-btn" type="button" data-tab="security">Security</button>
    <button class="tab-btn" type="button" data-tab="endpoints">Endpoints</button>
    <button class="tab-btn" type="button" data-tab="dns">DNS</button>
    <button class="tab-btn" type="button" data-tab="tls">TLS / QUIC</button>
    <button class="tab-btn" type="button" data-tab="flows">Flows</button>
  </nav>

  <section id="overview" class="tab-panel active">
    <div class="section-title"><div><h2>Overview</h2><p>Capture summary and traffic classification.</p></div></div>
    <div class="grid">
      <div class="card"><div class="label">Packets</div><div class="metric">__PACKETS__</div></div>
      <div class="card"><div class="label">Flows</div><div class="metric">__FLOWS__</div></div>
      <div class="card"><div class="label">Bytes</div><div class="metric">__BYTES__</div></div>
      <div class="card"><div class="label">Backend</div><div class="metric">__BACKEND__</div></div>
      <div class="card"><div class="label">Findings</div><div class="metric">__FINDING_COUNT__</div></div>
    </div>
    <div class="panel"><h3>Traffic Categories</h3><div class="table-wrap"><table><thead><tr><th>Likely Traffic</th><th>Flows</th></tr></thead><tbody>__CATEGORY_ROWS__</tbody></table></div></div>
    <div class="panel"><h3>Interpretation Note</h3><p class="note">Application classification is evidence-based. Encryption, shared CDNs, ECH, encrypted DNS, NAT, VPNs, and missing hostname metadata can reduce certainty.</p></div>
  </section>

  <section id="security" class="tab-panel">
    <div class="section-title"><div><h2>Security Findings</h2><p>Explainable defensive heuristics triggered by the observed traffic.</p></div></div>
    <div class="panel">__FINDINGS__</div>
  </section>

  <section id="endpoints" class="tab-panel">
    <div class="section-title"><div><h2>Endpoint Inventory</h2><p>Top observed endpoints, scope, activity, peers, and protocols.</p></div></div>
    <div class="panel"><div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Scope</th><th>Activity</th><th>Packets</th><th>Bytes</th><th>Peers</th><th>Protocols</th></tr></thead><tbody>__ENDPOINT_ROWS__</tbody></table></div></div>
  </section>

  <section id="dns" class="tab-panel">
    <div class="section-title"><div><h2>DNS Analytics</h2><p>Visible DNS activity. Encrypted DNS can hide normal resolver metadata.</p></div></div>
    <div class="grid">
      <div class="card"><div class="label">DNS Queries</div><div class="metric">__DNS_QUERIES__</div></div>
      <div class="card"><div class="label">DNS Responses</div><div class="metric">__DNS_RESPONSES__</div></div>
      <div class="card"><div class="label">Unique Domains</div><div class="metric">__DNS_UNIQUE__</div></div>
      <div class="card"><div class="label">NXDOMAIN</div><div class="metric">__NXDOMAIN__</div></div>
    </div>
    <div class="panel"><h3>Top DNS Queries</h3><div class="table-wrap"><table><thead><tr><th>Query</th><th>Count</th></tr></thead><tbody>__DNS_ROWS__</tbody></table></div></div>
  </section>

  <section id="tls" class="tab-panel">
    <div class="section-title"><div><h2>TLS / QUIC Intelligence</h2><p>Metadata only; PacketSageX does not defeat encryption.</p></div></div>
    <div class="grid">
      <div class="card"><div class="label">TLS Packets</div><div class="metric">__TLS_PACKETS__</div></div>
      <div class="card"><div class="label">QUIC Packets</div><div class="metric">__QUIC_PACKETS__</div></div>
      <div class="card"><div class="label">Visible Server Names</div><div class="metric">__SNI_UNIQUE__</div></div>
    </div>
    <div class="panel"><h3>Visible Server Names (SNI)</h3><div class="table-wrap"><table><thead><tr><th>Server Name</th><th>Count</th></tr></thead><tbody>__SNI_ROWS__</tbody></table></div></div>
  </section>

  <section id="flows" class="tab-panel">
    <div class="section-title"><div><h2>Flows</h2><p>Search and sort the complete flow inventory.</p></div></div>
    <div class="panel">
      <div class="controls screen-only"><input id="searchBox" type="search" placeholder="Search Source, Destination, Protocol, Packets, Bytes, Likely Traffic, Confidence"><select id="sortField"><option value="bytes">Sort by Bytes</option><option value="packets">Sort by Packets</option><option value="confidence">Sort by Confidence</option><option value="source">Sort by Source</option><option value="destination">Sort by Destination</option><option value="protocol">Sort by Protocol</option><option value="traffic">Sort by Likely Traffic</option></select><button id="topBtn" class="active" type="button">Top ↓</button><button id="bottomBtn" type="button">Bottom ↑</button><span id="resultCount"></span></div>
      <div class="table-wrap"><table id="flowTable"><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Likely Traffic</th><th>Confidence</th></tr></thead><tbody>__FLOW_ROWS__</tbody></table></div>
    </div>
  </section>

  <div class="footer">PacketSageX · Defensive Network Traffic Intelligence &amp; Forensics</div>
</main>
<script>
(()=>{
  const tabButtons=Array.from(document.querySelectorAll('.tab-btn'));
  const panels=Array.from(document.querySelectorAll('.tab-panel'));
  function activateTab(name){
    tabButtons.forEach(btn=>btn.classList.toggle('active',btn.dataset.tab===name));
    panels.forEach(panel=>panel.classList.toggle('active',panel.id===name));
    if(history.replaceState) history.replaceState(null,'','#'+name);
  }
  tabButtons.forEach(btn=>btn.addEventListener('click',()=>activateTab(btn.dataset.tab)));
  const initial=location.hash.slice(1);
  if(panels.some(panel=>panel.id===initial)) activateTab(initial);

  document.getElementById('printBtn').addEventListener('click',()=>window.print());

  const tbody=document.querySelector('#flowTable tbody');
  const rows=Array.from(tbody.querySelectorAll('tr')).filter(row=>row.children.length===7);
  const search=document.getElementById('searchBox');
  const sort=document.getElementById('sortField');
  const top=document.getElementById('topBtn');
  const bottom=document.getElementById('bottomBtn');
  const count=document.getElementById('resultCount');
  let dir='top';
  const idx={source:0,destination:1,protocol:2,packets:3,bytes:4,traffic:5,confidence:6};
  const numeric=new Set(['packets','bytes','confidence']);
  function value(row,field){const text=row.children[idx[field]].textContent.trim();return numeric.has(field)?Number(text.replace(/[^0-9.-]/g,''))||0:text.toLowerCase()}
  function render(){
    const query=search.value.trim().toLowerCase(),field=sort.value;
    const out=rows.filter(row=>!query||Array.from(row.children).some(cell=>cell.textContent.toLowerCase().includes(query)));
    out.sort((a,b)=>{const av=value(a,field),bv=value(b,field),cmp=numeric.has(field)?av-bv:String(av).localeCompare(String(bv));return dir==='top'?-cmp:cmp});
    tbody.replaceChildren(...out);
    count.textContent=`${out.length} of ${rows.length} flows`;
  }
  search.addEventListener('input',render);sort.addEventListener('change',render);
  top.addEventListener('click',()=>{dir='top';top.classList.add('active');bottom.classList.remove('active');render()});
  bottom.addEventListener('click',()=>{dir='bottom';bottom.classList.add('active');top.classList.remove('active');render()});
  render();
})();
</script>
</body>
</html>'''

    replacements = {
        "__SOURCE__": source,
        "__PACKETS__": f"{int(report.get('packet_count', 0) or 0):,}",
        "__FLOWS__": f"{int(report.get('flow_count', 0) or 0):,}",
        "__BYTES__": f"{int(report.get('byte_count', 0) or 0):,}",
        "__BACKEND__": backend,
        "__INTERFACE__": interface,
        "__GENERATED__": html.escape(generated),
        "__FINDING_COUNT__": f"{len(findings):,}",
        "__FINDINGS__": finding_html,
        "__CATEGORY_ROWS__": category_rows,
        "__ENDPOINT_ROWS__": endpoint_rows,
        "__DNS_QUERIES__": f"{int(dns.get('query_packets', 0) or 0):,}",
        "__DNS_RESPONSES__": f"{int(dns.get('response_packets', 0) or 0):,}",
        "__DNS_UNIQUE__": f"{int(dns.get('unique_queries', 0) or 0):,}",
        "__NXDOMAIN__": f"{int(dns.get('nxdomain_count', 0) or 0):,}",
        "__DNS_ROWS__": dns_rows,
        "__TLS_PACKETS__": f"{int(encrypted.get('tls_packets', 0) or 0):,}",
        "__QUIC_PACKETS__": f"{int(encrypted.get('quic_packets', 0) or 0):,}",
        "__SNI_UNIQUE__": f"{int(encrypted.get('unique_server_names', 0) or 0):,}",
        "__SNI_ROWS__": sni_rows,
        "__FLOW_ROWS__": flow_rows,
    }
    for key, value in replacements.items():
        document = document.replace(key, value)

    target.write_text(document, encoding="utf-8")
    return target
