from packetsagex.intelligence import TrafficClassifier
from packetsagex.models import FlowSummary, PacketRecord


def test_youtube_domain_classification():
    flow = FlowSummary("x", "10.0.0.2", "1.1.1.1", "TLS", 50000, 443, packets=12, bytes=10000)
    packet = PacketRecord(1, 1.0, 500, "10.0.0.2", "1.1.1.1", "TLS", 50000, 443, server_name="rr1---sn.googlevideo.com")
    name, confidence, evidence = TrafficClassifier().classify(flow, [packet])
    assert name == "YouTube / Google Video"
    assert confidence >= 70
    assert evidence
