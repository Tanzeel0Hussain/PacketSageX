from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8'); return target


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True)
    fields=['src','dst','protocol','src_port','dst_port','packets','bytes','duration','classification','confidence','evidence']
    with target.open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=fields); writer.writeheader()
        for flow in report.get('flows',[]):
            row={key:flow.get(key,'') for key in fields}
            if isinstance(row['evidence'],list): row['evidence']='; '.join(row['evidence'])
            writer.writerow(row)
    return target


def _td(value: object) -> str:
    return f'<td>{html.escape(str(value))}</td>'


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    target=Path(path); target.parent.mkdir(parents=True,exist_ok=True)
    flows=report.get('flows',[]); findings=report.get('security_findings',[]); inventory=report.get('endpoint_inventory',[])
    dns=report.get('dns_analytics',{}) or {}; encrypted=report.get('tls_quic_intelligence',{}) or {}
    flow_rows=''.join('<tr>'+''.join([
        _td(flow.get('src','')),_td(flow.get('dst','')),_td(flow.get('protocol','')),_td(int(flow.get('packets',0) or 0)),
        _td(int(flow.get('bytes',0) or 0)),_td(flow.get('classification','')),_td(f"{int(flow.get('confidence',0) or 0)}%")])+'</tr>' for flow in flows)
    endpoint_rows=''.join('<tr>'+''.join([_td(x.get('endpoint','')),_td(x.get('scope','')),_td(x.get('activity','')),_td(x.get('packets',0)),_td(x.get('bytes',0)),_td(x.get('peer_count',0)),_td(', '.join(x.get('protocols',[])))])+'</tr>' for x in inventory[:50]) or '<tr><td colspan="7">No endpoint data.</td></tr>'
    dns_rows=''.join('<tr>'+_td(x.get('query',''))+_td(x.get('count',0))+'</tr>' for x in dns.get('top_queries',[])[:25]) or '<tr><td colspan="2">No DNS queries observed.</td></tr>'
    sni_rows=''.join('<tr>'+_td(x.get('server_name',''))+_td(x.get('count',0))+'</tr>' for x in encrypted.get('top_server_names',[])[:25]) or '<tr><td colspan="2">No visible TLS SNI observed.</td></tr>'
    finding_html=''.join(f"<li><strong>{html.escape(str(i.get('severity','')).upper())}</strong> — {html.escape(str(i.get('title','')))}: {html.escape(str(i.get('evidence','')))}</li>" for i in findings) or '<li>No heuristic findings triggered.</li>'
    source=html.escape(str(report.get('source',''))); backend=html.escape(str(report.get('backend','n/a'))); interface=html.escape(str(report.get('interface','n/a')))
    document='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PacketSageX Report</title>
<style>:root{color-scheme:dark;--bg:#07101d;--panel:#0d1b2d;--line:#253650;--text:#e8f0fb;--muted:#9db0c9;--accent:#58d7ff}*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text)}main{max-width:1500px;margin:auto;padding:28px}h1{margin-bottom:6px}h2{margin-top:30px}.sub,.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:20px 0}.card{background:var(--panel);border:1px solid var(--line);padding:16px;border-radius:14px}.metric{font-size:1.4rem;font-weight:700}.label{color:var(--muted);font-size:.8rem;text-transform:uppercase}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px;margin-top:12px}table{border-collapse:collapse;width:100%;min-width:850px;background:#091522}th,td{padding:10px 12px;border-bottom:1px solid #1d2d45;text-align:left;white-space:nowrap}th{background:#102039;color:#cfe8ff}.controls{display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:14px;background:var(--panel);border:1px solid var(--line);border-radius:14px;position:sticky;top:0;z-index:3}input,select,button{background:#081522;color:var(--text);border:1px solid #31445f;border-radius:9px;padding:10px 12px}input{flex:1 1 420px}button.active{border-color:var(--accent);color:var(--accent)}#resultCount{margin-left:auto;color:var(--muted)}ul{line-height:1.65}</style></head><body><main>
<h1>PacketSageX Analysis Report</h1><div class="sub">__SOURCE__</div>
<section class="grid"><div class="card"><div class="label">Packets</div><div class="metric">__PACKETS__</div></div><div class="card"><div class="label">Flows</div><div class="metric">__FLOWS__</div></div><div class="card"><div class="label">Bytes</div><div class="metric">__BYTES__</div></div><div class="card"><div class="label">Backend</div><div class="metric">__BACKEND__</div></div><div class="card"><div class="label">Interface</div><div class="metric">__INTERFACE__</div></div></section>
<h2>Security Findings</h2><div class="card"><ul>__FINDINGS__</ul></div>
<h2>Endpoint Inventory</h2><div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Scope</th><th>Activity</th><th>Packets</th><th>Bytes</th><th>Peers</th><th>Protocols</th></tr></thead><tbody>__ENDPOINT_ROWS__</tbody></table></div>
<h2>DNS Analytics</h2><section class="grid"><div class="card"><div class="label">DNS Queries</div><div class="metric">__DNS_QUERIES__</div></div><div class="card"><div class="label">DNS Responses</div><div class="metric">__DNS_RESPONSES__</div></div><div class="card"><div class="label">Unique Domains</div><div class="metric">__DNS_UNIQUE__</div></div><div class="card"><div class="label">NXDOMAIN</div><div class="metric">__NXDOMAIN__</div></div></section><div class="table-wrap"><table><thead><tr><th>Query</th><th>Count</th></tr></thead><tbody>__DNS_ROWS__</tbody></table></div>
<h2>TLS / QUIC Intelligence</h2><section class="grid"><div class="card"><div class="label">TLS Packets</div><div class="metric">__TLS_PACKETS__</div></div><div class="card"><div class="label">QUIC Packets</div><div class="metric">__QUIC_PACKETS__</div></div><div class="card"><div class="label">Visible Server Names</div><div class="metric">__SNI_UNIQUE__</div></div></section><div class="table-wrap"><table><thead><tr><th>Visible Server Name (SNI)</th><th>Count</th></tr></thead><tbody>__SNI_ROWS__</tbody></table></div>
<h2>Flows</h2><div class="controls"><input id="searchBox" type="search" placeholder="Search Source, Destination, Protocol, Packets, Bytes, Likely Traffic, Confidence"><select id="sortField"><option value="bytes">Sort by Bytes</option><option value="packets">Sort by Packets</option><option value="confidence">Sort by Confidence</option><option value="source">Sort by Source</option><option value="destination">Sort by Destination</option><option value="protocol">Sort by Protocol</option><option value="traffic">Sort by Likely Traffic</option></select><button id="topBtn" class="active">Top ↓</button><button id="bottomBtn">Bottom ↑</button><span id="resultCount"></span></div>
<div class="table-wrap"><table id="flowTable"><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Likely Traffic</th><th>Confidence</th></tr></thead><tbody>__FLOW_ROWS__</tbody></table></div><p class="muted">Application classification is evidence-based and may be uncertain for encrypted or shared infrastructure.</p>
</main><script>(()=>{const tbody=document.querySelector('#flowTable tbody'),rows=Array.from(tbody.querySelectorAll('tr')),search=document.getElementById('searchBox'),sort=document.getElementById('sortField'),top=document.getElementById('topBtn'),bottom=document.getElementById('bottomBtn'),count=document.getElementById('resultCount');let dir='top';const idx={source:0,destination:1,protocol:2,packets:3,bytes:4,traffic:5,confidence:6},num=new Set(['packets','bytes','confidence']);function value(r,f){const t=r.children[idx[f]].textContent.trim();return num.has(f)?Number(t.replace(/[^0-9.-]/g,''))||0:t.toLowerCase()}function render(){const q=search.value.trim().toLowerCase(),f=sort.value;const out=rows.filter(r=>!q||Array.from(r.children).some(c=>c.textContent.toLowerCase().includes(q)));out.sort((a,b)=>{const av=value(a,f),bv=value(b,f),x=num.has(f)?av-bv:String(av).localeCompare(String(bv));return dir==='top'?-x:x});tbody.replaceChildren(...out);count.textContent=`${out.length} of ${rows.length} flows`}search.addEventListener('input',render);sort.addEventListener('change',render);top.addEventListener('click',()=>{dir='top';top.classList.add('active');bottom.classList.remove('active');render()});bottom.addEventListener('click',()=>{dir='bottom';bottom.classList.add('active');top.classList.remove('active');render()});render()})();</script></body></html>'''
    replacements={
        '__SOURCE__':source,'__PACKETS__':f"{int(report.get('packet_count',0) or 0):,}",'__FLOWS__':f"{int(report.get('flow_count',0) or 0):,}",'__BYTES__':f"{int(report.get('byte_count',0) or 0):,}",'__BACKEND__':backend,'__INTERFACE__':interface,'__FINDINGS__':finding_html,
        '__ENDPOINT_ROWS__':endpoint_rows,'__DNS_QUERIES__':f"{int(dns.get('query_packets',0) or 0):,}",'__DNS_RESPONSES__':f"{int(dns.get('response_packets',0) or 0):,}",'__DNS_UNIQUE__':f"{int(dns.get('unique_queries',0) or 0):,}",'__NXDOMAIN__':f"{int(dns.get('nxdomain_count',0) or 0):,}",'__DNS_ROWS__':dns_rows,
        '__TLS_PACKETS__':f"{int(encrypted.get('tls_packets',0) or 0):,}",'__QUIC_PACKETS__':f"{int(encrypted.get('quic_packets',0) or 0):,}",'__SNI_UNIQUE__':f"{int(encrypted.get('unique_server_names',0) or 0):,}",'__SNI_ROWS__':sni_rows,'__FLOW_ROWS__':flow_rows,
    }
    for key,value in replacements.items(): document=document.replace(key,value)
    target.write_text(document,encoding='utf-8'); return target
