const $ = (id) => document.getElementById(id);
let currentReport = null;
const demo = {
  packet_count:1248, flow_count:37, byte_count:1843200, backend:"tshark",
  traffic_categories:{"Web / HTTPS":15,"YouTube / Google Video":8,"DNS":4,"Unknown":10},
  security_findings:[{severity:"medium",title:"Potential cleartext HTTP traffic",evidence:"Observed service port 80 in capture metadata."}],
  flows:[
    {src:"192.168.1.10",dst:"142.250.180.14",protocol:"QUIC",packets:258,bytes:850000,classification:"YouTube / Google Video",confidence:91},
    {src:"192.168.1.10",dst:"1.1.1.1",protocol:"DNS",packets:74,bytes:10320,classification:"DNS",confidence:85},
    {src:"192.168.1.10",dst:"104.18.32.47",protocol:"TLS",packets:143,bytes:220400,classification:"Web / HTTPS",confidence:58}
  ]
};
function fmt(n){return new Intl.NumberFormat().format(Number(n||0));}
function esc(value){return String(value??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));}
function render(report){currentReport=report;$("stats").innerHTML=[
  ["Packets",fmt(report.packet_count)],["Flows",fmt(report.flow_count)],["Bytes",fmt(report.byte_count)],["Backend",esc(report.backend||"report")]
].map(([k,v])=>`<div class="stat"><b>${v}</b><span>${k}</span></div>`).join("");
const cats=Object.entries(report.traffic_categories||{});const max=Math.max(1,...cats.map(([,v])=>v));
$("categories").innerHTML=cats.length?cats.map(([name,count])=>`<div class="bar"><div class="bar-top"><span>${esc(name)}</span><span>${fmt(count)}</span></div><div class="track"><div class="fill" style="width:${Math.max(4,count/max*100)}%"></div></div></div>`).join(""):"<span class='empty'>No categories in report.</span>";
const findings=report.security_findings||[];$("findings").innerHTML=findings.length?findings.map(f=>`<div class="finding ${esc(f.severity)}"><strong>${esc((f.severity||"info").toUpperCase())} · ${esc(f.title)}</strong><small>${esc(f.evidence)}</small></div>`).join(""):"<span class='empty'>No heuristic findings triggered.</span>";renderFlows();}
function renderFlows(){const q=$("filter").value.toLowerCase();const flows=(currentReport?.flows||[]).filter(f=>JSON.stringify(f).toLowerCase().includes(q));$("flowRows").innerHTML=flows.slice(0,200).map(f=>`<tr><td>${esc(f.src)}</td><td>${esc(f.dst)}</td><td>${esc(f.protocol)}</td><td>${fmt(f.packets)}</td><td>${fmt(f.bytes)}</td><td>${esc(f.classification)}</td><td class="confidence">${fmt(f.confidence)}%</td></tr>`).join("");}
$("reportFile").addEventListener("change",async e=>{const file=e.target.files[0];if(!file)return;try{render(JSON.parse(await file.text()));}catch(err){alert("Invalid PacketSageX JSON: "+err.message);}});
$("nmapFile").addEventListener("change",async e=>{const file=e.target.files[0];if(!file)return;try{const doc=new DOMParser().parseFromString(await file.text(),"application/xml");if(doc.querySelector("parsererror"))throw new Error("Invalid XML");const hosts=[...doc.querySelectorAll("host")].map(h=>{const addr=h.querySelector("address")?.getAttribute("addr")||"unknown";const name=h.querySelector("hostname")?.getAttribute("name")||"";const ports=[...h.querySelectorAll("ports > port")].map(p=>({port:p.getAttribute("portid"),proto:p.getAttribute("protocol"),state:p.querySelector("state")?.getAttribute("state")||"",service:p.querySelector("service")?.getAttribute("name")||""}));return{addr,name,ports};});$("nmapOutput").innerHTML=hosts.length?hosts.map(h=>`<div class="finding"><strong>${esc(h.addr)} ${h.name?`(${esc(h.name)})`:""}</strong><small>${h.ports.map(p=>`${esc(p.port)}/${esc(p.proto)} ${esc(p.state)} ${esc(p.service)}`).join(" · ")||"No ports listed"}</small></div>`).join(""):"No hosts found.";}catch(err){alert("Could not parse Nmap XML: "+err.message);}});
$("demoBtn").addEventListener("click",()=>render(demo));$("clearBtn").addEventListener("click",()=>{currentReport=null;$("stats").innerHTML="";$("categories").innerHTML="Load a report to begin.";$("findings").innerHTML="No report loaded.";$("flowRows").innerHTML="";$("nmapOutput").innerHTML="Load an Nmap XML file exported with <code>nmap -oX scan.xml …</code>.";});$("filter").addEventListener("input",renderFlows);render(demo);
