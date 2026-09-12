from __future__ import annotations

import json
from importlib.resources import files
from typing import Iterable

from ..models import FlowSummary, PacketRecord


class TrafficClassifier:
    def __init__(self) -> None:
        path = files("packetsagex.intelligence").joinpath("signatures.json")
        self.rules = json.loads(path.read_text(encoding="utf-8"))

    def classify(self, flow: FlowSummary, packets: Iterable[PacketRecord]) -> tuple[str, int, list[str]]:
        packet_list = list(packets)
        domains = " ".join(
            value.lower()
            for packet in packet_list
            for value in (packet.dns_query, packet.server_name, packet.http_host)
            if value
        )
        ports = {port for port in (flow.src_port, flow.dst_port) if port is not None}
        protocol = flow.protocol.upper()
        best = ("Unknown", 15, ["No strong application signature matched"])

        for rule in self.rules:
            score = 0
            evidence: list[str] = []
            domain_hits = [suffix for suffix in rule.get("domains", []) if suffix.lower() in domains]
            if domain_hits:
                score += min(70, 45 + 5 * len(domain_hits))
                evidence.append(f"domain hint: {domain_hits[0]}")
            port_hits = sorted(ports.intersection(rule.get("ports", [])))
            if port_hits:
                score += 22
                evidence.append(f"service port: {port_hits[0]}")
            protocols = {p.upper() for p in rule.get("protocols", [])}
            if protocol in protocols:
                score += 18
                evidence.append(f"protocol: {protocol}")
            if rule.get("min_packets") and flow.packets >= rule["min_packets"]:
                score += 5
                evidence.append("flow volume pattern")

            if score > best[1]:
                best = (rule["name"], min(98, score), evidence)

        if best[0] == "Unknown":
            generic = self._generic(flow)
            if generic[1] > best[1]:
                best = generic
        return best

    @staticmethod
    def _generic(flow: FlowSummary) -> tuple[str, int, list[str]]:
        ports = {p for p in (flow.src_port, flow.dst_port) if p is not None}
        if ports & {80, 443, 8080, 8443}:
            return "Web / HTTPS", 58, ["common web service port"]
        if ports & {53, 853}:
            return "DNS", 85, ["DNS service port"]
        if ports & {22}:
            return "SSH", 90, ["SSH service port"]
        if ports & {25, 465, 587, 993, 995}:
            return "Email", 76, ["email service port"]
        if ports & {123}:
            return "NTP", 88, ["NTP service port"]
        if ports & {3478, 5349}:
            return "Real-time Communication", 68, ["STUN/TURN service port"]
        return "Unknown", 20, ["insufficient metadata for reliable attribution"]
