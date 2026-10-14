from typing import List, Tuple
from scapy.all import TCP
from netprobe.scenarios.base import BaseScenario, TestResult


def _parse_resp(resp):
    if resp and resp.haslayer(TCP):
        return str(resp[TCP].flags), f"Ack={resp[TCP].ack}, Seq={resp[TCP].seq}, Win={resp[TCP].window}"
    return "NONE", "No response packet captured (Drop/Timeout)"


class ScenarioTCP01_Standard(BaseScenario):
    scenario_id = "TCP-01"
    name = "Standard Valid TCP Packet"
    category = "TCP"
    field_tested = "Standard Fields"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", payload=b"NetProbe Standard Ping")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Compliant RFC 793",
            mutated_val="Compliant RFC 793",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP02_InvalidSeq(BaseScenario):
    scenario_id = "TCP-02"
    name = "Invalid / Desynchronized Sequence Number"
    category = "TCP"
    field_tested = "Sequence Number"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        bad_seq = (stack.seq + 0x10000000) & 0xFFFFFFFF
        pkt = stack.build_packet(flags="PA", seq=bad_seq, payload=b"Desync Seq Payload")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Seq={stack.seq}",
            mutated_val=f"Seq={bad_seq}",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP03_ExtremeSeq(BaseScenario):
    scenario_id = "TCP-03"
    name = "Extreme Boundary Sequence Number (0xFFFFFFFF)"
    category = "TCP"
    field_tested = "Sequence Number"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        extreme_seq = 0xFFFFFFFF
        pkt = stack.build_packet(flags="PA", seq=extreme_seq, payload=b"Max Seq Test")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Seq={stack.seq}",
            mutated_val=f"Seq={extreme_seq}",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP04_InvalidAck(BaseScenario):
    scenario_id = "TCP-04"
    name = "Invalid Acknowledgment Number"
    category = "TCP"
    field_tested = "Acknowledgment Number"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        bad_ack = (stack.ack - 500000) & 0xFFFFFFFF
        pkt = stack.build_packet(flags="PA", ack=bad_ack, payload=b"Bad Ack Payload")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Ack={stack.ack}",
            mutated_val=f"Ack={bad_ack}",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP05_ExtremeAck(BaseScenario):
    scenario_id = "TCP-05"
    name = "Extreme Boundary Acknowledgment Number (0xFFFFFFFF)"
    category = "TCP"
    field_tested = "Acknowledgment Number"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", ack=0xFFFFFFFF, payload=b"Max Ack Test")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Ack={stack.ack}",
            mutated_val="Ack=0xFFFFFFFF",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP06_DataOffset(BaseScenario):
    scenario_id = "TCP-06"
    name = "Invalid Data Offset (DataOffset < 5)"
    category = "TCP"
    field_tested = "Data Offset"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        # Minimum valid data offset is 5 (20 bytes). Offset 4 is invalid.
        pkt = stack.build_packet(flags="PA", data_offset=4, payload=b"Illegal Offset")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="dataofs=5 (20B)",
            mutated_val="dataofs=4 (16B - Invalid)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP07_ReservedBits(BaseScenario):
    scenario_id = "TCP-07"
    name = "Non-zero Reserved Bits (0b111)"
    category = "TCP"
    field_tested = "Reserved Bits"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", reserved=7, payload=b"Reserved bits test")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="reserved=0",
            mutated_val="reserved=7 (0b111)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP08_FlagCWR(BaseScenario):
    scenario_id = "TCP-08"
    name = "Flag Mutation CWR (Congestion Window Reduced)"
    category = "TCP"
    field_tested = "Flags: CWR"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="CWA", payload=b"CWR flag active")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=CWA",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP09_FlagECE(BaseScenario):
    scenario_id = "TCP-09"
    name = "Flag Mutation ECE (ECN-Echo)"
    category = "TCP"
    field_tested = "Flags: ECE"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="EA", payload=b"ECE flag active")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=EA",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP10_FlagURG(BaseScenario):
    scenario_id = "TCP-10"
    name = "Flag Mutation URG"
    category = "TCP"
    field_tested = "Flags: URG"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="UPA", urgptr=10, payload=b"URG flag test")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA, urgptr=0",
            mutated_val="flags=UPA, urgptr=10",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP11_FlagACK_Cleared(BaseScenario):
    scenario_id = "TCP-11"
    name = "Data Packet with ACK Flag Cleared"
    category = "TCP"
    field_tested = "Flags: ACK"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="P", payload=b"Data without ACK flag")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=P (ACK cleared)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP12_FlagPSH(BaseScenario):
    scenario_id = "TCP-12"
    name = "Flag Mutation PSH Toggle"
    category = "TCP"
    field_tested = "Flags: PSH"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="A", payload=b"Payload without PSH")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=A (PSH off)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP13_FlagRST(BaseScenario):
    scenario_id = "TCP-13"
    name = "Premature RST Injection"
    category = "TCP"
    field_tested = "Flags: RST"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="R", payload=b"")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=R (Reset)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP14_FlagSYN_InSession(BaseScenario):
    scenario_id = "TCP-14"
    name = "Unexpected SYN on Established Session"
    category = "TCP"
    field_tested = "Flags: SYN"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="S", payload=b"")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=S (SYN inside session)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP15_FlagFIN(BaseScenario):
    scenario_id = "TCP-15"
    name = "Early FIN Flag Injection"
    category = "TCP"
    field_tested = "Flags: FIN"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="FA", payload=b"")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=FA",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP16_FlagCombinations(BaseScenario):
    scenario_id = "TCP-16"
    name = "Abnormal Flag Combination (SYN+FIN / Xmas Scan)"
    category = "TCP"
    field_tested = "Flags: Combination"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        # Xmas packet: FIN + PSH + URG
        pkt = stack.build_packet(flags="FPU", payload=b"Xmas Tree Packet")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="flags=PA",
            mutated_val="flags=FPU (FIN+PSH+URG)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP17_WindowBoundary(BaseScenario):
    scenario_id = "TCP-17"
    name = "Window Size Boundary (Window = 0 / Zero Window Probe)"
    category = "TCP"
    field_tested = "Window Size"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", window=0, payload=b"Zero Window Data")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"window={stack.window}",
            mutated_val="window=0",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP18_ChecksumCorrupt(BaseScenario):
    scenario_id = "TCP-18"
    name = "Corrupted TCP Checksum"
    category = "TCP"
    field_tested = "Checksum"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", chksum=0xDEAD, payload=b"Corrupted Checksum Data")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Valid RFC Checksum",
            mutated_val="chksum=0xDEAD (Forced Invalid)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP19_UrgentPointer(BaseScenario):
    scenario_id = "TCP-19"
    name = "Urgent Pointer Mismatch (URG=0 with non-zero UrgPtr)"
    category = "TCP"
    field_tested = "Urgent Pointer"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        pkt = stack.build_packet(flags="PA", urgptr=0x1234, payload=b"Mismatched UrgPtr")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="urgptr=0, flags=PA",
            mutated_val="urgptr=0x1234, flags=PA (URG unset)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTCP20_TCPOptions(BaseScenario):
    scenario_id = "TCP-20"
    name = "Malformed TCP Options (Invalid Option Length)"
    category = "TCP"
    field_tested = "TCP Options"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        # Standard options + raw malformed option bytes: option kind 254 with invalid len 0
        malformed_options = [("MSS", 1460), ("WScale", 7), (254, b"")]
        pkt = stack.build_packet(flags="PA", options=malformed_options, payload=b"Malformed Options")
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Standard Options",
            mutated_val="Malformed Option [Kind=254, Len=0]",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


ALL_TCP_SCENARIOS = [
    ScenarioTCP01_Standard,
    ScenarioTCP02_InvalidSeq,
    ScenarioTCP03_ExtremeSeq,
    ScenarioTCP04_InvalidAck,
    ScenarioTCP05_ExtremeAck,
    ScenarioTCP06_DataOffset,
    ScenarioTCP07_ReservedBits,
    ScenarioTCP08_FlagCWR,
    ScenarioTCP09_FlagECE,
    ScenarioTCP10_FlagURG,
    ScenarioTCP11_FlagACK_Cleared,
    ScenarioTCP12_FlagPSH,
    ScenarioTCP13_FlagRST,
    ScenarioTCP14_FlagSYN_InSession,
    ScenarioTCP15_FlagFIN,
    ScenarioTCP16_FlagCombinations,
    ScenarioTCP17_WindowBoundary,
    ScenarioTCP18_ChecksumCorrupt,
    ScenarioTCP19_UrgentPointer,
    ScenarioTCP20_TCPOptions,
]
