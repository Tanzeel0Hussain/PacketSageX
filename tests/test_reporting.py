from packetsagex.reporting import write_html


def test_html_report_has_search_and_top_bottom_controls(tmp_path):
    report = {
        "source": "demo.pcap",
        "backend": "live-scapy",
        "interface": "any",
        "packet_count": 10,
        "flow_count": 1,
        "byte_count": 2048,
        "security_findings": [],
        "flows": [
            {
                "src": "10.0.0.2",
                "dst": "1.1.1.1",
                "protocol": "TCP",
                "packets": 10,
                "bytes": 2048,
                "classification": "Web / HTTPS",
                "confidence": 58,
            }
        ],
    }

    target = write_html(report, tmp_path / "report.html")
    text = target.read_text(encoding="utf-8")

    assert 'id="searchBox"' in text
    assert 'id="topBtn"' in text
    assert 'id="bottomBtn"' in text
    assert "Likely Traffic" in text
    assert "10.0.0.2" in text
    assert "Web / HTTPS" in text
