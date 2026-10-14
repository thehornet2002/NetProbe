from typing import List
from scapy.all import TCP
from netprobe.scenarios.base import BaseScenario, TestResult
from netprobe.protocols.tls_records import TLSRecordBuilder, TLSVersion


def _parse_resp(resp):
    if resp and resp.haslayer(TCP):
        tcp = resp[TCP]
        return str(tcp.flags), f"TCP Ack={tcp.ack}, PayloadBytes={len(bytes(tcp.payload))}"
    return "NONE", "No response received"


class ScenarioCombo01_TLS13_ZeroWindow(BaseScenario):
    scenario_id = "COMBO-01"
    name = "TLS 1.3 ClientHello with TCP Zero Window"
    category = "COMBO"
    field_tested = "TLS 1.3 + TCP Window=0"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_3)
        pkt = stack.build_packet(flags="PA", window=0, payload=ch)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="TLS 1.3 + Normal Window",
            mutated_val="TLS 1.3 ClientHello + TCP Window=0",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioCombo02_TLS12_BadSeq(BaseScenario):
    scenario_id = "COMBO-02"
    name = "TLS 1.2 ClientHello with Out-of-Order TCP Seq"
    category = "COMBO"
    field_tested = "TLS 1.2 + TCP Bad Seq"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
        bad_seq = (stack.seq + 0x08000000) & 0xFFFFFFFF
        pkt = stack.build_packet(flags="PA", seq=bad_seq, payload=ch)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Valid Seq={stack.seq}",
            mutated_val=f"TLS 1.2 + Bad Seq={bad_seq}",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioCombo03_TLS_CorruptChecksum(BaseScenario):
    scenario_id = "COMBO-03"
    name = "TLS ClientHello with Corrupted TCP Checksum"
    category = "COMBO"
    field_tested = "TLS + TCP Checksum"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
        pkt = stack.build_packet(flags="PA", chksum=0xDEAD, payload=ch)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Valid Checksum",
            mutated_val="TLS 1.2 + Checksum=0xDEAD",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


ALL_COMBO_SCENARIOS = [
    ScenarioCombo01_TLS13_ZeroWindow,
    ScenarioCombo02_TLS12_BadSeq,
    ScenarioCombo03_TLS_CorruptChecksum,
]
