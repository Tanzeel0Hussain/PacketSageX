from __future__ import annotations

from datetime import datetime
import html
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote
from xml.sax.saxutils import escape as xml_escape


def _safe(value: object) -> str:
    return str(value if value is not None else "")


def _imports():
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import KeepTogether, LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError(
            'Professional PDF export requires ReportLab. Reinstall PacketSageX with: python -m pip install -e ".[dev]"'
        ) from exc
    return locals()


def write_pdf(report: dict[str, Any], path: str | Path) -> Path:
    """Write a polished native PDF instead of relying on browser printing."""
    rl = _imports()
    colors, TA_CENTER, TA_LEFT = rl["colors"], rl["TA_CENTER"], rl["TA_LEFT"]
    A4, landscape, ParagraphStyle = rl["A4"], rl["landscape"], rl["ParagraphStyle"]
    getSampleStyleSheet, mm = rl["getSampleStyleSheet"], rl["mm"]
    KeepTogether, LongTable, PageBreak = rl["KeepTogether"], rl["LongTable"], rl["PageBreak"]
    Paragraph, SimpleDocTemplate, Spacer = rl["Paragraph"], rl["SimpleDocTemplate"], rl["Spacer"]
    Table, TableStyle = rl["Table"], rl["TableStyle"]

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    page_size = landscape(A4)
    doc = SimpleDocTemplate(
        str(target), pagesize=page_size,
        rightMargin=12 * mm, leftMargin=12 * mm, topMargin=17 * mm, bottomMargin=16 * mm,
        title="PacketSageX Network Forensics Report", author="PacketSageX",
        subject="Defensive network traffic intelligence and forensics report",
    )

    base = getSampleStyleSheet()
    title = ParagraphStyle("PSXTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=29, leading=34, textColor=colors.HexColor("#083344"), alignment=TA_CENTER, spaceAfter=10)
    subtitle = ParagraphStyle("PSXSubtitle", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=colors.HexColor("#087f8c"), alignment=TA_CENTER, spaceAfter=20)
    h1 = ParagraphStyle("PSXH1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=colors.HexColor("#0b3a4a"), spaceBefore=4, spaceAfter=9)
    h2 = ParagraphStyle("PSXH2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#0f6170"), spaceBefore=7, spaceAfter=6)
    body = ParagraphStyle("PSXBody", parent=base["BodyText"], fontName="Helvetica", fontSize=8.8, leading=12, textColor=colors.HexColor("#25313b"))
    small = ParagraphStyle("PSXSmall", parent=body, fontSize=7.3, leading=9.2)
    table_header = ParagraphStyle("PSXTH", parent=small, fontName="Helvetica-Bold", textColor=colors.white, alignment=TA_LEFT)
    table_cell = ParagraphStyle("PSXTD", parent=small, textColor=colors.HexColor("#1f2933"))
    metric_label = ParagraphStyle("PSXML", parent=small, fontName="Helvetica-Bold", textColor=colors.HexColor("#5a6770"), alignment=TA_CENTER)
    metric_value = ParagraphStyle("PSXMV", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=14, leading=16, textColor=colors.HexColor("#073642"), alignment=TA_CENTER)
    cover_meta = ParagraphStyle("PSXCM", parent=body, fontSize=9.2, leading=13)

    def p(value: object, style=table_cell):
        return Paragraph(xml_escape(_safe(value)), style)

    def section(value: str):
        return Paragraph(xml_escape(value), h1)

    def report_table(headers: list[str], rows: list[list[object]], widths: list[float] | None = None):
        data = [[Paragraph(xml_escape(x), table_header) for x in headers]]
        data.extend([[p(value) for value in row] for row in rows])
        klass = LongTable if len(data) > 20 else Table
        table = klass(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b5967")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b9c5ca")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f7f8")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    source, backend, interface = _safe(report.get("source", "")), _safe(report.get("backend", "n/a")), _safe(report.get("interface", "n/a"))
    packet_count, flow_count, byte_count = int(report.get("packet_count", 0) or 0), int(report.get("flow_count", 0) or 0), int(report.get("byte_count", 0) or 0)
    findings, categories = report.get("security_findings", []) or [], report.get("traffic_categories", {}) or {}
    inventory, dns = report.get("endpoint_inventory", []) or [], report.get("dns_analytics", {}) or {}
    encrypted, flows = report.get("tls_quic_intelligence", {}) or {}, report.get("flows", []) or []

    story: list[Any] = [
        Spacer(1, 22 * mm), Paragraph("PACKETSAGEX", title),
        Paragraph("NETWORK TRAFFIC INTELLIGENCE &amp; FORENSICS", subtitle), Spacer(1, 5 * mm),
    ]
    meta = Table([
        [p("Report Type", cover_meta), p("Defensive Network Forensics Analysis", cover_meta)],
        [p("Source Capture", cover_meta), p(source, cover_meta)],
        [p("Analysis Backend", cover_meta), p(backend, cover_meta)],
        [p("Interface", cover_meta), p(interface, cover_meta)],
        [p("Generated", cover_meta), p(generated, cover_meta)],
    ], colWidths=[48 * mm, 160 * mm], hAlign="CENTER")
    meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f8f9")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#8aaeb5")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#c8d6da")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    cover_note = ParagraphStyle("PSXCoverNote", parent=body, alignment=TA_CENTER, textColor=colors.HexColor("#52636b"))
    story += [
        meta, Spacer(1, 10 * mm),
        Paragraph("This document is generated directly by PacketSageX as a structured PDF. It is not a browser printout. Application attribution is evidence-based and may be uncertain when traffic uses shared infrastructure, ECH, encrypted DNS, NAT or VPNs.", cover_note),
        PageBreak(), section("Executive Summary"),
    ]

    metrics = [
        [Paragraph(x, metric_label) for x in ["PACKETS", "FLOWS", "BYTES", "DNS QUERIES", "SECURITY FINDINGS"]],
        [Paragraph(x, metric_value) for x in [f"{packet_count:,}", f"{flow_count:,}", f"{byte_count:,}", f"{int(dns.get('query_packets', 0) or 0):,}", f"{len(findings):,}"]],
    ]
    metric_table = Table(metrics, colWidths=[47 * mm] * 5, hAlign="LEFT")
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f2f7f8")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#afc6cc")),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d2dfe2")),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [metric_table, Spacer(1, 7 * mm), Paragraph("Traffic Classification", h2)]
    category_rows = [[name, count] for name, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)] or [["No traffic categories available", 0]]
    story += [report_table(["Likely Traffic", "Flows"], category_rows, [150 * mm, 35 * mm]), Spacer(1, 5 * mm), section("Security Findings")]

    if findings:
        for item in findings:
            severity, title_text, evidence = str(item.get("severity", "info")).upper(), str(item.get("title", "Finding")), str(item.get("evidence", ""))
            story.append(KeepTogether([
                Paragraph(f"{xml_escape(severity)} — {xml_escape(title_text)}", h2),
                Paragraph(xml_escape(evidence) or "No additional evidence recorded.", body), Spacer(1, 3 * mm),
            ]))
    else:
        story.append(Paragraph("No heuristic security findings were triggered for this capture.", body))

    story += [PageBreak(), section("Endpoint Inventory")]
    endpoint_rows = [[x.get("endpoint", ""), x.get("scope", ""), x.get("activity", ""), x.get("packets", 0), x.get("bytes", 0), x.get("peer_count", 0), ", ".join(x.get("protocols", []))] for x in inventory[:100]] or [["No endpoint data", "", "", "", "", "", ""]]
    story.append(report_table(["Endpoint", "Scope", "Activity", "Packets", "Bytes", "Peers", "Protocols"], endpoint_rows, [42 * mm, 28 * mm, 32 * mm, 20 * mm, 25 * mm, 18 * mm, 70 * mm]))

    story += [PageBreak(), section("DNS Analytics")]
    dns_summary = [["DNS Queries", int(dns.get("query_packets", 0) or 0)], ["DNS Responses", int(dns.get("response_packets", 0) or 0)], ["Unique Domains", int(dns.get("unique_queries", 0) or 0)], ["NXDOMAIN", int(dns.get("nxdomain_count", 0) or 0)]]
    story += [report_table(["Metric", "Value"], dns_summary, [70 * mm, 35 * mm]), Spacer(1, 5 * mm), Paragraph("Top DNS Queries", h2)]
    dns_rows = [[x.get("query", ""), x.get("count", 0)] for x in dns.get("top_queries", [])[:50]] or [["No visible DNS queries", 0]]
    story.append(report_table(["Query", "Count"], dns_rows, [165 * mm, 30 * mm]))

    story += [PageBreak(), section("TLS / QUIC Intelligence")]
    tls_summary = [["TLS Packets", int(encrypted.get("tls_packets", 0) or 0)], ["QUIC Packets", int(encrypted.get("quic_packets", 0) or 0)], ["Visible Server Names", int(encrypted.get("unique_server_names", 0) or 0)]]
    story += [report_table(["Metric", "Value"], tls_summary, [70 * mm, 35 * mm]), Spacer(1, 5 * mm), Paragraph("Visible Server Names (SNI)", h2)]
    sni_rows = [[x.get("server_name", ""), x.get("count", 0)] for x in encrypted.get("top_server_names", [])[:50]] or [["No visible TLS SNI observed", 0]]
    story.append(report_table(["Server Name", "Count"], sni_rows, [165 * mm, 30 * mm]))

    story += [PageBreak(), section("Flow Details"), Paragraph("Classification confidence reflects visible metadata and heuristic evidence.", body), Spacer(1, 3 * mm)]
    flow_rows = [[x.get("src", ""), x.get("dst", ""), x.get("protocol", ""), int(x.get("packets", 0) or 0), int(x.get("bytes", 0) or 0), x.get("classification", ""), f"{int(x.get('confidence', 0) or 0)}%"] for x in flows] or [["No flows", "", "", "", "", "", ""]]
    story.append(report_table(["Source", "Destination", "Protocol", "Packets", "Bytes", "Likely Traffic", "Confidence"], flow_rows, [39 * mm, 39 * mm, 20 * mm, 18 * mm, 24 * mm, 72 * mm, 23 * mm]))

    def on_page(canvas, document) -> None:
        canvas.saveState(); width, height = page_size
        canvas.setTitle("PacketSageX Network Forensics Report"); canvas.setAuthor("PacketSageX")
        if document.page > 1:
            canvas.setStrokeColor(colors.HexColor("#9bb7bd")); canvas.setLineWidth(0.5)
            canvas.line(12 * mm, height - 11 * mm, width - 12 * mm, height - 11 * mm)
            canvas.setFont("Helvetica-Bold", 8); canvas.setFillColor(colors.HexColor("#0b5967"))
            canvas.drawString(12 * mm, height - 8.5 * mm, "PACKETSAGEX · NETWORK FORENSICS REPORT")
        canvas.setStrokeColor(colors.HexColor("#c3d2d6")); canvas.setLineWidth(0.4)
        canvas.line(12 * mm, 10 * mm, width - 12 * mm, 10 * mm)
        canvas.setFont("Helvetica", 7.5); canvas.setFillColor(colors.HexColor("#52636b"))
        canvas.drawString(12 * mm, 6.5 * mm, "PacketSageX · Defensive Network Forensics")
        canvas.drawRightString(width - 12 * mm, 6.5 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return target


def attach_pdf_actions(html_path: str | Path, pdf_path: str | Path) -> Path:
    """Replace browser-print action with links to the native PDF report."""
    html_target = Path(html_path)
    pdf_target = Path(pdf_path).resolve()
    try:
        href = quote(os.path.relpath(pdf_target, html_target.parent.resolve()).replace(os.sep, "/"))
    except (OSError, ValueError):
        href = pdf_target.as_uri()

    text = html_target.read_text(encoding="utf-8")
    old_button = '<button id="printBtn" class="action" type="button">Print / Save PDF</button>'
    actions = (
        f'<a class="action" href="{html.escape(href)}" target="_blank" rel="noopener">Open Professional PDF</a>'
        f'<a class="action" href="{html.escape(href)}" download>Save PDF</a>'
    )
    text = text.replace(old_button, actions)
    text = text.replace(
        "document.getElementById('printBtn').addEventListener('click',()=>window.print());",
        "// Professional PDF is generated natively by PacketSageX.",
    )
    html_target.write_text(text, encoding="utf-8")
    return html_target
