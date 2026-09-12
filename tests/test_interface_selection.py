from packetsagex.cli import _select_live_interface


def test_any_prefers_default_non_loopback_interface():
    assert _select_live_interface("any", ["lo", "wlp2s0", "eth0"], "wlp2s0") == "wlp2s0"


def test_any_falls_back_to_first_non_loopback_interface():
    assert _select_live_interface("any", ["lo", "eth0"], "missing0") == "eth0"


def test_explicit_interface_is_preserved():
    assert _select_live_interface("wlan7", ["lo", "eth0"], "eth0") == "wlan7"
