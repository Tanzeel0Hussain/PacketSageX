from packetsagex.models import FlowSummary
from packetsagex.security import security_findings


def test_cleartext_service_finding():
    flow = FlowSummary("x", "a", "b", "TCP", 50000, 23, packets=3, bytes=100)
    findings = security_findings([], [flow])
    assert any(item["type"] == "cleartext-service" for item in findings)
