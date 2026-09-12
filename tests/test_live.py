from packetsagex.live import LiveMonitor
from packetsagex.models import PacketRecord


def test_live_monitor_tracks_packets_flows_and_web_classification():
    monitor = LiveMonitor()
    packet = PacketRecord(
        number=1,
        timestamp=1.0,
        length=512,
        src="10.0.0.2",
        dst="1.1.1.1",
        protocol="TCP",
        src_port=50000,
        dst_port=443,
    )

    label, confidence = monitor.add_record(packet)
    snap = monitor.snapshot()

    assert snap["packet_count"] == 1
    assert snap["byte_count"] == 512
    assert snap["flow_count"] == 1
    assert label == "Web / HTTPS"
    assert confidence >= 50
