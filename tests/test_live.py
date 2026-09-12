from pathlib import Path

from packetsagex.live import LiveMonitor, _new_session_directory
from packetsagex.models import PacketRecord


def _sample_packet() -> PacketRecord:
    return PacketRecord(
        number=1,
        timestamp=1.0,
        length=512,
        src="10.0.0.2",
        dst="1.1.1.1",
        protocol="TCP",
        src_port=50000,
        dst_port=443,
    )


def test_live_monitor_tracks_packets_flows_and_web_classification():
    monitor = LiveMonitor()
    label, confidence = monitor.add_record(_sample_packet())
    snap = monitor.snapshot()

    assert snap["packet_count"] == 1
    assert snap["byte_count"] == 512
    assert snap["flow_count"] == 1
    assert label == "Web / HTTPS"
    assert confidence >= 50


def test_live_monitor_builds_report():
    monitor = LiveMonitor()
    monitor.add_record(_sample_packet())
    report = monitor.to_report(interface="any", capture_path=Path("capture.pcap"))

    assert report["backend"] == "live-scapy"
    assert report["packet_count"] == 1
    assert report["flow_count"] == 1
    assert report["flows"][0]["src"] == "10.0.0.2"
    assert report["flows"][0]["dst"] == "1.1.1.1"
    assert report["flows"][0]["classification"] == "Web / HTTPS"


def test_timestamped_session_directories_are_unique(tmp_path):
    first = _new_session_directory(tmp_path)
    second = _new_session_directory(tmp_path)

    assert first != second
    assert first.parent == tmp_path
    assert second.parent == tmp_path
    assert first.is_dir()
    assert second.is_dir()
