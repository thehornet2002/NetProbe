from typing import List
from scapy.all import TCP
from netprobe.scenarios.base import BaseScenario, TestResult
from netprobe.protocols.tls_records import TLSRecordBuilder, TLSVersion, TLSContentType
from netprobe.core.byte_buffer import ByteBuffer


def _parse_resp(resp):
    if resp and resp.haslayer(TCP):
        tcp = resp[TCP]
        payload = bytes(tcp.payload)
        resp_type = "TCP-ACK"
        if len(payload) >= 5:
            content_type = payload[0]
            if content_type == 21:
                resp_type = "TLS-ALERT"
            elif content_type == 22:
                resp_type = "TLS-HANDSHAKE"
            else:
                resp_type = f"TLS-CT-{content_type}"
        return str(tcp.flags), f"{resp_type} (Bytes: {len(payload)}, Ack={tcp.ack})"
    return "NONE", "No response received (Timeout / Dropped)"


class ScenarioTLS01_StandardHello(BaseScenario):
    def __init__(self, target_version: int = TLSVersion.TLS_1_2):
        self.target_version = target_version
        v_name = TLSVersion.get_name(target_version)
        self.scenario_id = f"TLS-{v_name.replace(' ', '')}-Standard"
        self.name = f"Standard {v_name} ClientHello"
        self.category = "TLS"
        self.field_tested = f"{v_name} Handshake"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_payload = TLSRecordBuilder.build_client_hello(target_version=self.target_version)
        pkt = stack.build_packet(flags="PA", payload=ch_payload)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Compliant ClientHello",
            mutated_val=TLSVersion.get_name(self.target_version),
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS02_InvalidContentType(BaseScenario):
    scenario_id = "TLS-Invalid-ContentType"
    name = "Invalid TLS Record ContentType (0xFF)"
    category = "TLS"
    field_tested = "Record ContentType"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_raw = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
        buf = ByteBuffer(ch_raw)
        buf.replace_byte(0, 0xFF)  # Invalid content type
        pkt = stack.build_packet(flags="PA", payload=buf.to_bytes())
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="ContentType=22 (Handshake)",
            mutated_val="ContentType=0xFF (255 - Unknown)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS03_RecordLengthMismatch(BaseScenario):
    scenario_id = "TLS-Length-Mismatch"
    name = "Record Length Exceeding Fragment Size (Underflow/Mismatch)"
    category = "TLS"
    field_tested = "Record Length"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_raw = TLSRecordBuilder.build_client_hello(
            target_version=TLSVersion.TLS_1_2,
            record_len_override=4096  # Claims 4096 bytes but actual payload is ~200B
        )
        pkt = stack.build_packet(flags="PA", payload=ch_raw)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Length = len(fragment)",
            mutated_val="Length = 4096 (Mismatch with fragment)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS04_BoundaryLengthMax(BaseScenario):
    scenario_id = "TLS-Length-Boundary-65535"
    name = "Boundary Record Length (0xFFFF)"
    category = "TLS"
    field_tested = "Record Length"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_raw = TLSRecordBuilder.build_client_hello(
            target_version=TLSVersion.TLS_1_2,
            record_len_override=0xFFFF
        )
        pkt = stack.build_packet(flags="PA", payload=ch_raw)
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Length <= 16384",
            mutated_val="Length = 0xFFFF (65535)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS05_TruncatedFragment(BaseScenario):
    scenario_id = "TLS-Truncated-Record"
    name = "Prematurely Truncated Record Fragment"
    category = "TLS"
    field_tested = "Record Fragment"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_raw = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
        buf = ByteBuffer(ch_raw)
        buf.truncate(len(buf) // 2)  # Truncate halfway through ClientHello
        pkt = stack.build_packet(flags="PA", payload=buf.to_bytes())
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val=f"Full Fragment ({len(ch_raw)} bytes)",
            mutated_val=f"Truncated ({len(buf)} bytes)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS06_BitFlipFuzz(BaseScenario):
    scenario_id = "TLS-Fuzz-BitFlip"
    name = "ByteBuffer Bit-Flipping Fuzz on ClientHello"
    category = "TLS"
    field_tested = "Handshake Body"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        ch_raw = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
        buf = ByteBuffer(ch_raw)
        # Flip bits in the middle of handshake body
        offset = min(15, len(buf) - 1)
        buf.flip_bit(offset, 3)
        buf.flip_bit(offset + 4, 7)
        pkt = stack.build_packet(flags="PA", payload=buf.to_bytes())
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Original Handshake Bytes",
            mutated_val=f"Bits inverted at byte {offset} & {offset+4}",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


class ScenarioTLS07_UnexpectedMessage(BaseScenario):
    scenario_id = "TLS-Unexpected-AppData"
    name = "Unexpected Application Data Prior to Handshake"
    category = "TLS"
    field_tested = "Message Sequence"

    def execute(self, stack, direction: str = "Client -> Server") -> TestResult:
        # Send raw application data without completing handshake
        rec = TLSRecordBuilder.build_record(
            content_type=TLSContentType.APPLICATION_DATA,
            version=TLSVersion.TLS_1_2,
            payload=b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
        )
        pkt = stack.build_packet(flags="PA", payload=rec.to_bytes())
        resp, delay_ms, attempts, status = stack.send_and_wait_response(pkt)
        flags, details = _parse_resp(resp)
        return TestResult(
            scenario_id=self.scenario_id,
            name=self.name,
            category=self.category,
            field_tested=self.field_tested,
            original_val="Expected ClientHello (22)",
            mutated_val="Premature ApplicationData (23)",
            direction=direction,
            attempts_used=attempts,
            rtt_ms=delay_ms,
            response_status=status,
            peer_response_flags=flags,
            details=details
        )


ALL_TLS_SCENARIOS = [
    lambda: ScenarioTLS01_StandardHello(TLSVersion.TLS_1_0),
    lambda: ScenarioTLS01_StandardHello(TLSVersion.TLS_1_1),
    lambda: ScenarioTLS01_StandardHello(TLSVersion.TLS_1_2),
    lambda: ScenarioTLS01_StandardHello(TLSVersion.TLS_1_3),
    ScenarioTLS02_InvalidContentType,
    ScenarioTLS03_RecordLengthMismatch,
    ScenarioTLS04_BoundaryLengthMax,
    ScenarioTLS05_TruncatedFragment,
    ScenarioTLS06_BitFlipFuzz,
    ScenarioTLS07_UnexpectedMessage,
]
