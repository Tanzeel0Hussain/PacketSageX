from packetsagex.reporting import write_html


def test_html_report_has_tabs_print_and_intelligence_sections(tmp_path):
    report={
        'source':'demo.pcap','backend':'live-scapy','interface':'any','packet_count':10,'flow_count':1,'byte_count':2048,
        'traffic_categories':{'Web / HTTPS':1},
        'security_findings':[],
        'endpoint_inventory':[{'endpoint':'10.0.0.2','scope':'private/local','activity':'mostly-sender','packets':10,'bytes':2048,'peer_count':1,'protocols':['TCP']}],
        'dns_analytics':{'query_packets':2,'response_packets':2,'unique_queries':1,'nxdomain_count':0,'top_queries':[{'query':'example.com','count':2}]},
        'tls_quic_intelligence':{'tls_packets':5,'quic_packets':1,'unique_server_names':1,'top_server_names':[{'server_name':'example.com','count':1}]},
        'flows':[{'src':'10.0.0.2','dst':'1.1.1.1','protocol':'TCP','packets':10,'bytes':2048,'classification':'Web / HTTPS','confidence':58}],
    }
    text=write_html(report,tmp_path/'report.html').read_text(encoding='utf-8')
    assert 'id="searchBox"' in text and 'id="topBtn"' in text and 'id="bottomBtn"' in text
    assert 'data-tab="overview"' in text and 'data-tab="flows"' in text
    assert 'id="printBtn"' in text and 'window.print()' in text and '@media print' in text
    assert 'Endpoint Inventory' in text and 'DNS Analytics' in text and 'TLS / QUIC Intelligence' in text
    assert 'Traffic Categories' in text and 'example.com' in text and 'Web / HTTPS' in text
