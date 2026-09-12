# Professional PDF Reports

PacketSageX generates native, paginated PDF reports with ReportLab. The PDF is created directly from the analysis data; it is not a browser Print-to-PDF capture.

A professional PDF contains a branded cover page, capture metadata, executive summary, traffic classification, security findings, endpoint inventory, DNS analytics, TLS/QUIC intelligence, complete flow details, repeated table headers, page numbers, and PacketSageX headers/footers.

When an offline analysis is exported with `--html`, PacketSageX automatically creates a sibling `.pdf` and the HTML report shows **Open Professional PDF** and **Save PDF** actions. You can also choose an explicit PDF path with `--pdf`.

Live sessions create `report.pdf` in the same timestamped report directory after capture stops.

The PDF intentionally avoids browser URL/date print chrome so it can be shared, archived, submitted, or printed as a normal forensic report.
