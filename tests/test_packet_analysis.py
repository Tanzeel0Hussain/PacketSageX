from packetsagex.models import PacketRecord
from packetsagex.packet_analysis import build_packet_analysis, describe_packet, write_packets_csv, attach_packet_explorer
from packetsagex.reporting import write_html


def _packets():
    return [
        PacketRecord(number=1, timestamp=100.0, length=74, src="10.0.0.2", dst="1.1.1.1", protocol="DNS", src_port=53000, dst_port=53, dns_query="example.com"),
        PacketRecord(number=2, timestamp=100.25, length=120, src="1.1.1.1", dst="10.0.0.2", protocol="DNS", src_port=53, dst_port=53000, dns_query="example.com", dns_is_response=True, dns_rcode="0"),
        PacketRecord(number=3, timestamp=101.0, length=512, src="10.0.0.2", dst="93.184.216.34", protocol="TLS", src_port=50000, dst_port=443, server_name="example.com", tls_version="0x0304"),
    ]


def test_packet_analysis_builds_wireshark_level_summary():
    info = build_packet_analysis(_packets())
    assert info["duration_seconds"] == 1.0
    assert info["protocol_counts"]["DNS"] == 2
    assert info["dns_packets"] == 2
    assert info["tls_metadata_packets"] == 1
    assert info["sampled_packets"] == 3
    assert "DNS query for example.com" in info["samples"][0]["summary"]
    assert "TLS handshake/SNI example.com" in info["samples"][2]["summary"]


def test_packet_csv_and_html_explorer(tmp_path):
    report = {
        "source": "capture.pcapng",
        "backend": "tshark",
        "packet_count": 3,
        "flow_count": 1,
        "byte_count": 706,
        "traffic_categories": {"Web / HTTPS": 1},
        "security_findings": [],
        "endpoint_inventory": [],
        "dns_analytics": {},
        "tls_quic_intelligence": {},
        "flows": [],
        "packet_analysis": build_packet_analysis(_packets()),
    }
    csv_path = write_packets_csv(report, tmp_path / "packets.csv")
    assert "example.com" in csv_path.read_text(encoding="utf-8")

    html_path = write_html(report, tmp_path / "report.html")
    attach_packet_explorer(html_path, report)
    text = html_path.read_text(encoding="utf-8")
    assert 'data-tab="packets"' in text
    assert 'id="packetSearch"' in text
    assert "Packet Explorer" in text
    assert "DNS query for example.com" in text


def test_describe_tcp_packet():
    packet = PacketRecord(number=1, timestamp=1.0, length=60, src="10.0.0.2", dst="8.8.8.8", protocol="TCP", src_port=50000, dst_port=443, tcp_flags="ACK")
    text = describe_packet(packet)
    assert "50000" in text and "443" in text and "ACK" in text
