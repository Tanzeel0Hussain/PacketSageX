const $ = (id) => document.getElementById(id);
let current = null;

const fmt = (n) => new Intl.NumberFormat().format(Number(n || 0));
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const ip4 = (dv, o) => `${dv.getUint8(o)}.${dv.getUint8(o+1)}.${dv.getUint8(o+2)}.${dv.getUint8(o+3)}`;
const ip6 = (dv, o) => Array.from({length:8},(_,i)=>dv.getUint16(o+i*2).toString(16)).join(":");

function setStatus(text, kind="") { const el=$("status"); el.textContent=text; el.className=`status ${kind}`.trim(); }
function serviceLabel(proto, sp, dp, dns="") {
  const ports=[sp,dp];
  if(dns) return "DNS";
  if((proto==="UDP"||proto==="QUIC") && ports.includes(443)) return "QUIC / HTTPS";
  if(proto==="TCP" && ports.includes(443)) return "Web / HTTPS";
  if(proto==="TCP" && ports.includes(80)) return "Web / HTTP";
  if(ports.includes(53)) return "DNS";
  if(ports.includes(123)) return "NTP";
  if(ports.includes(22)) return "SSH";
  if(ports.includes(25)||ports.includes(465)||ports.includes(587)) return "Email / SMTP";
  if(ports.includes(110)||ports.includes(995)) return "Email / POP3";
  if(ports.includes(143)||ports.includes(993)) return "Email / IMAP";
  if(ports.includes(67)||ports.includes(68)) return "DHCP";
  if(ports.includes(5353)) return "mDNS";
  return proto || "Unknown";
}
function packetSummary(p) {
  if(p.dns_query) return `DNS ${p.dns_response?"response":"query"}: ${p.dns_query}`;
  const left=p.src_port!=null?`${p.src}:${p.src_port}`:p.src;
  const right=p.dst_port!=null?`${p.dst}:${p.dst_port}`:p.dst;
  if(p.protocol==="TCP") return `TCP ${left} → ${right}${p.tcp_flags?` flags=${p.tcp_flags}`:""}`;
  if(p.protocol==="UDP") return `UDP ${left} → ${right}`;
  if(p.protocol==="QUIC") return `QUIC / UDP 443 ${left} → ${right}`;
  return `${p.protocol} ${p.src||"?"} → ${p.dst||"?"}`;
}
function dnsName(dv, offset, end) {
  const labels=[]; let pos=offset; let jumps=0;
  while(pos<end && jumps<40){ const len=dv.getUint8(pos++); if(len===0) break; if((len&0xc0)===0xc0){ if(pos>=end) break; const ptr=((len&0x3f)<<8)|dv.getUint8(pos); pos=ptr; jumps++; continue; } if(pos+len>end) break; let s=""; for(let i=0;i<len;i++){const c=dv.getUint8(pos+i); s+=c>=32&&c<127?String.fromCharCode(c):"?";} labels.push(s); pos+=len; jumps++; }
  return labels.join(".");
}
function tcpFlags(v){const names=[]; if(v&0x01)names.push("FIN");if(v&0x02)names.push("SYN");if(v&0x04)names.push("RST");if(v&0x08)names.push("PSH");if(v&0x10)names.push("ACK");if(v&0x20)names.push("URG");if(v&0x40)names.push("ECE");if(v&0x80)names.push("CWR");return names.join(",");}

function decodeFrame(bytes, number, timestamp, wireLength, linkType=1){
  const dv=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength); const p={number,timestamp,length:wireLength||bytes.byteLength,src:"",dst:"",protocol:"OTHER",src_port:null,dst_port:null,dns_query:"",dns_response:false,tcp_flags:""};
  if(linkType!==1 || bytes.byteLength<14){p.protocol=`LINKTYPE ${linkType}`;p.summary=packetSummary(p);return p;}
  let ether=dv.getUint16(12); let off=14;
  if((ether===0x8100||ether===0x88a8)&&bytes.byteLength>=18){ether=dv.getUint16(16);off=18;}
  if(ether===0x0806){p.protocol="ARP";p.summary="ARP traffic";return p;}
  let next=0, transport=0;
  if(ether===0x0800 && bytes.byteLength>=off+20){const ihl=(dv.getUint8(off)&15)*4;if(ihl<20||bytes.byteLength<off+ihl)return p;p.src=ip4(dv,off+12);p.dst=ip4(dv,off+16);next=dv.getUint8(off+9);transport=off+ihl;}
  else if(ether===0x86dd && bytes.byteLength>=off+40){p.src=ip6(dv,off+8);p.dst=ip6(dv,off+24);next=dv.getUint8(off+6);transport=off+40;}
  else {p.protocol=`ETH 0x${ether.toString(16).padStart(4,"0")}`;p.summary=packetSummary(p);return p;}
  if(next===6 && bytes.byteLength>=transport+20){p.protocol="TCP";p.src_port=dv.getUint16(transport);p.dst_port=dv.getUint16(transport+2);p.tcp_flags=tcpFlags(dv.getUint8(transport+13));}
  else if(next===17 && bytes.byteLength>=transport+8){p.protocol="UDP";p.src_port=dv.getUint16(transport);p.dst_port=dv.getUint16(transport+2);const payload=transport+8;if((p.src_port===53||p.dst_port===53||p.src_port===5353||p.dst_port===5353)&&bytes.byteLength>=payload+13){p.dns_response=!!(dv.getUint16(payload+2)&0x8000);p.dns_query=dnsName(dv,payload+12,bytes.byteLength);p.protocol="DNS";} else if(p.src_port===443||p.dst_port===443){p.protocol="QUIC";} }
  else if(next===1){p.protocol="ICMP";} else if(next===58){p.protocol="ICMPV6";} else {p.protocol=`IP ${next}`;}
  p.summary=packetSummary(p); return p;
}

function parsePcap(buffer){
  const dv=new DataView(buffer); if(dv.byteLength<24) throw new Error("PCAP file is too small.");
  const b0=dv.getUint32(0,false); let little=false,nano=false;
  if(b0===0xa1b2c3d4){little=false;} else if(b0===0xd4c3b2a1){little=true;} else if(b0===0xa1b23c4d){little=false;nano=true;} else if(b0===0x4d3cb2a1){little=true;nano=true;} else throw new Error("Not a supported classic PCAP file.");
  const linkType=dv.getUint32(20,little); let o=24,n=1; const packets=[];
  while(o+16<=dv.byteLength){const sec=dv.getUint32(o,little),frac=dv.getUint32(o+4,little),cap=dv.getUint32(o+8,little),orig=dv.getUint32(o+12,little);o+=16;if(cap>dv.byteLength-o)break;const slice=new Uint8Array(buffer,o,cap);packets.push(decodeFrame(slice,n++,sec+frac/(nano?1e9:1e6),orig,linkType));o+=cap;}
  if(!packets.length) throw new Error("No packets were found in this PCAP."); return packets;
}

function parsePcapng(buffer){
  const dv=new DataView(buffer); if(dv.byteLength<28||dv.getUint32(0,false)!==0x0a0d0d0a) throw new Error("Not a supported PCAPNG file.");
  let o=0,little=true,n=1; const interfaces=[]; const packets=[];
  while(o+12<=dv.byteLength){
    const typeBE=dv.getUint32(o,false); if(typeBE===0x0a0d0d0a){const bomBE=dv.getUint32(o+8,false); if(bomBE===0x1a2b3c4d)little=false; else if(bomBE===0x4d3c2b1a)little=true; else throw new Error("Unsupported PCAPNG byte order.");}
    const type=dv.getUint32(o,little), len=dv.getUint32(o+4,little); if(len<12||o+len>dv.byteLength)break;
    if(type===1 && len>=20){interfaces.push({linkType:dv.getUint16(o+8,little),ts:1e-6});}
    if(type===6 && len>=32){const iface=dv.getUint32(o+8,little),hi=dv.getUint32(o+12,little),lo=dv.getUint32(o+16,little),cap=dv.getUint32(o+20,little),orig=dv.getUint32(o+24,little),start=o+28;if(start+cap<=o+len-4){const info=interfaces[iface]||{linkType:1,ts:1e-6};const ticks=hi*4294967296+lo;packets.push(decodeFrame(new Uint8Array(buffer,start,cap),n++,ticks*info.ts,orig,info.linkType));}}
    o+=len;
  }
  if(!packets.length) throw new Error("No Enhanced Packet Blocks were found. This mini analyzer supports common Ethernet PCAPNG captures."); return packets;
}

function buildReport(packets,fileName,sourceType){
  const protocols={},categories={},flows=new Map(); let bytes=0; const first=packets[0]?.timestamp||0,last=packets.at(-1)?.timestamp||first;
  for(const p of packets){bytes+=p.length;protocols[p.protocol]=(protocols[p.protocol]||0)+1;const label=serviceLabel(p.protocol,p.src_port,p.dst_port,p.dns_query);categories[label]=(categories[label]||0)+1;const a=`${p.src}:${p.src_port??0}`,b=`${p.dst}:${p.dst_port??0}`;const pair=[a,b].sort();const key=`${pair[0]}|${pair[1]}|${p.protocol}`;let f=flows.get(key);if(!f){f={src:p.src,dst:p.dst,protocol:p.protocol,packets:0,bytes:0,classification:label};flows.set(key,f);}f.packets++;f.bytes+=p.length;}
  return {file_name:fileName,source_type:sourceType,packet_count:packets.length,byte_count:bytes,duration_seconds:Math.max(0,last-first),protocol_counts:protocols,traffic_categories:categories,flows:[...flows.values()].sort((a,b)=>b.bytes-a.bytes),packets:packets.map(p=>({...p,time_offset:Math.max(0,p.timestamp-first)}))};
}
function fromPacketSageX(report,fileName){
  const pa=report.packet_analysis||{}; const samples=pa.samples||[]; const packets=samples.map(x=>({number:x.number,time_offset:x.time_offset||0,src:x.src||"",dst:x.dst||"",protocol:x.protocol||"",length:x.length||0,src_port:x.src_port,dst_port:x.dst_port,dns_query:x.dns_query||"",summary:x.summary||""}));
  return {file_name:fileName,source_type:"PacketSageX JSON",packet_count:report.packet_count||0,byte_count:report.byte_count||0,duration_seconds:pa.duration_seconds||0,protocol_counts:pa.protocol_counts||report.protocols||{},traffic_categories:report.traffic_categories||{},flows:report.flows||[],packets};
}
function bars(obj){const entries=Object.entries(obj||{}).sort((a,b)=>b[1]-a[1]);const max=Math.max(1,...entries.map(([,v])=>Number(v)));return entries.length?entries.slice(0,12).map(([k,v])=>`<div class="bar"><div class="bar-top"><span>${esc(k)}</span><span>${fmt(v)}</span></div><div class="track"><div class="fill" style="width:${Math.max(3,Number(v)/max*100)}%"></div></div></div>`).join(""):"<span class='muted'>No data.</span>";}
function render(report){current=report;$("results").classList.remove("hidden");$("fileTitle").textContent=report.file_name||"Capture analysis";const rate=report.duration_seconds>0?report.packet_count/report.duration_seconds:report.packet_count;$("stats").innerHTML=[["Packets",fmt(report.packet_count)],["Bytes",fmt(report.byte_count)],["Duration",`${Number(report.duration_seconds||0).toFixed(2)}s`],["Rate",`${rate.toFixed(1)}/s`],["Flows",fmt(report.flows?.length)],["Mode",esc(report.source_type||"Browser")]].map(([k,v])=>`<div class="stat"><b>${v}</b><span>${k}</span></div>`).join("");$("protocols").innerHTML=bars(report.protocol_counts);$("categories").innerHTML=bars(report.traffic_categories);renderFlows();renderPackets();}
function renderFlows(){if(!current)return;const q=$("flowFilter").value.trim().toLowerCase();const rows=(current.flows||[]).filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q)).slice(0,300);$("flowRows").innerHTML=rows.map(f=>`<tr><td>${esc(f.src)}</td><td>${esc(f.dst)}</td><td>${esc(f.protocol)}</td><td>${fmt(f.packets)}</td><td>${fmt(f.bytes)}</td><td>${esc(f.classification||"Unknown")}</td></tr>`).join("")||`<tr><td colspan="6" class="muted">No matching flows.</td></tr>`;}
function renderPackets(){if(!current)return;const q=$("packetFilter").value.trim().toLowerCase();const all=current.packets||[];const filtered=all.filter(x=>!q||JSON.stringify(x).toLowerCase().includes(q));const rows=filtered.slice(0,500);$("packetRows").innerHTML=rows.map(p=>`<tr><td>${fmt(p.number)}</td><td>${Number(p.time_offset??p.timestamp??0).toFixed(6)}</td><td>${esc(p.src)}${p.src_port!=null?`:${p.src_port}`:""}</td><td>${esc(p.dst)}${p.dst_port!=null?`:${p.dst_port}`:""}</td><td>${esc(p.protocol)}</td><td>${fmt(p.length)}</td><td>${esc(p.summary||packetSummary(p))}</td></tr>`).join("")||`<tr><td colspan="7" class="muted">No matching packet rows.</td></tr>`;$("packetNote").textContent=`Showing ${rows.length.toLocaleString()} of ${filtered.length.toLocaleString()} matching packet rows${all.length>500?" (table capped at 500 for browser performance)":""}.`;}
async function analyzeFile(file){
  if(file.size>100*1024*1024) throw new Error("The mini analyzer limits browser files to 100 MB. Use the PacketSageX CLI for larger captures.");
  setStatus(`Reading ${file.name}…`); const name=file.name.toLowerCase();
  if(name.endsWith(".json")){const obj=JSON.parse(await file.text());render(fromPacketSageX(obj,file.name));setStatus("PacketSageX JSON loaded locally.","ok");return;}
  const buffer=await file.arrayBuffer(); setStatus(`Analyzing ${file.name} locally…`); let packets;
  const magic=new DataView(buffer).getUint32(0,false); if(magic===0x0a0d0d0a) packets=parsePcapng(buffer); else packets=parsePcap(buffer);
  render(buildReport(packets,file.name,"Browser PCAP analyzer"));setStatus(`Done — ${packets.length.toLocaleString()} packets analyzed locally.`,"ok");
}
function demo(){const now=Date.now()/1000;const ps=[{number:1,timestamp:now,length:74,src:"192.168.1.10",dst:"1.1.1.1",protocol:"DNS",src_port:53001,dst_port:53,dns_query:"github.com",summary:"DNS query: github.com"},{number:2,timestamp:now+.018,length:118,src:"1.1.1.1",dst:"192.168.1.10",protocol:"DNS",src_port:53,dst_port:53001,dns_query:"github.com",dns_response:true,summary:"DNS response: github.com"},{number:3,timestamp:now+.080,length:66,src:"192.168.1.10",dst:"140.82.121.4",protocol:"TCP",src_port:50120,dst_port:443,tcp_flags:"SYN",summary:"TCP 192.168.1.10:50120 → 140.82.121.4:443 flags=SYN"},{number:4,timestamp:now+.145,length:1250,src:"140.82.121.4",dst:"192.168.1.10",protocol:"TCP",src_port:443,dst_port:50120,tcp_flags:"ACK",summary:"HTTPS/TLS transport packet"}];render(buildReport(ps,"demo-capture.pcap","Demo"));setStatus("Demo capture loaded.","ok");}
function clearAll(){current=null;$("results").classList.add("hidden");$("captureFile").value="";$("flowFilter").value="";$("packetFilter").value="";setStatus("Ready.");}
$("pickBtn").addEventListener("click",()=>$("captureFile").click());$("captureFile").addEventListener("change",async e=>{const f=e.target.files[0];if(!f)return;try{await analyzeFile(f);}catch(err){console.error(err);setStatus(err.message||String(err),"err");}});$("demoBtn").addEventListener("click",demo);$("clearBtn").addEventListener("click",clearAll);$("flowFilter").addEventListener("input",renderFlows);$("packetFilter").addEventListener("input",renderPackets);
$("exportBtn").addEventListener("click",()=>{if(!current)return;const summary={file_name:current.file_name,packet_count:current.packet_count,byte_count:current.byte_count,duration_seconds:current.duration_seconds,protocol_counts:current.protocol_counts,traffic_categories:current.traffic_categories,flows:current.flows};const blob=new Blob([JSON.stringify(summary,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="packetsagex-web-summary.json";a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);});
for(const ev of ["dragenter","dragover"]){$("dropZone").addEventListener(ev,e=>{e.preventDefault();$("dropZone").classList.add("drag");});}for(const ev of ["dragleave","drop"]){$("dropZone").addEventListener(ev,e=>{e.preventDefault();$("dropZone").classList.remove("drag");});}$("dropZone").addEventListener("drop",async e=>{const f=e.dataTransfer.files[0];if(!f)return;try{await analyzeFile(f);}catch(err){console.error(err);setStatus(err.message||String(err),"err");}});
demo();
