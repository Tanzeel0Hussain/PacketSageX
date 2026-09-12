from packetsagex.pdf_report import attach_pdf_actions, write_pdf
from packetsagex.reporting import write_html


def _report():
    return {
        'source': 'demo.pcap',
        'backend': 'tshark',
        'interface': 'wlp2s0',
        'packet_count': 10,
        'flow_count': 1,
        'byte_count': 2048,
        'traffic_categories': {'Web / HTTPS': 1},
        'security_findings': [
            {'severity': 'medium', 'title': 'Potential cleartext HTTP traffic', 'evidence': 'Observed TCP port 80 traffic.'}
        ],
        'endpoint_inventory': [
            {'endpoint': '10.0.0.2', 'scope': 'private/local', 'activity': 'mostly-sender', 'packets': 10, 'bytes': 2048, 'peer_count': 1, 'protocols': ['TCP']}
        ],
        'dns_analytics': {
            'query_packets': 2,
            'response_packets': 2,
            'unique_queries': 1,
            'nxdomain_count': 0,
            'top_queries': [{'query': 'example.com', 'count': 2}],
        },
        'tls_quic_intelligence': {
            'tls_packets': 5,
            'quic_packets': 1,
            'unique_server_names': 1,
            'top_server_names': [{'server_name': 'example.com', 'count': 1}],
        },
        'flows': [
            {'src': '10.0.0.2', 'dst': '1.1.1.1', 'protocol': 'TCP', 'packets': 10, 'bytes': 2048, 'classification': 'Web / HTTPS', 'confidence': 58}
        ],
    }


def test_html_report_has_tabs_search_and_native_pdf_actions(tmp_path):
    report = _report()
    html_path = write_html(report, tmp_path / 'report.html')
    pdf_path = write_pdf(report, tmp_path / 'report.pdf')
    attach_pdf_actions(html_path, pdf_path)
    text = html_path.read_text(encoding='utf-8')

    assert 'data-tab="overview"' in text
    assert 'data-tab="security"' in text
    assert 'data-tab="endpoints"' in text
    assert 'data-tab="dns"' in text
    assert 'data-tab="tls"' in text
    assert 'data-tab="flows"' in text
    assert 'id="searchBox"' in text
    assert 'Open Professional PDF' in text
    assert 'Save PDF' in text
    assert 'Print / Save PDF' not in text
    assert "getElementById('printBtn')" not in text


def test_native_pdf_can_be_written_directly(tmp_path):
    target = write_pdf(_report(), tmp_path / 'forensics.pdf')
    data = target.read_bytes()
    assert data.startswith(b'%PDF-')
    assert len(data) > 1000
