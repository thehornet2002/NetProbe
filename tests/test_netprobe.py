import os
import pytest
from netprobe.core.byte_buffer import ByteBuffer
from netprobe.protocols.tls_records import TLSRecordBuilder, TLSVersion, TLSContentType
from netprobe.core.tcp_stack import UserSpaceTCPStack
from netprobe.core.firewall import FirewallGuard
from netprobe.scenarios.tcp_scenarios import ALL_TCP_SCENARIOS
from netprobe.scenarios.tls_scenarios import ALL_TLS_SCENARIOS
from netprobe.scenarios.combo_scenarios import ALL_COMBO_SCENARIOS
from netprobe.scenarios.base import TestResult
from netprobe.report.collector import ReportCollector
from netprobe.report.html_generator import HTMLReportGenerator


def test_byte_buffer_operations():
    buf = ByteBuffer()
    buf.append_uint8(0x16)
    buf.append_uint16(0x0303)
    buf.append_uint24(100)
    buf.append_uint32(0xAABBCCDD)
    raw = buf.to_bytes()

    assert len(raw) == 1 + 2 + 3 + 4
    assert raw[0] == 0x16
    assert raw[1:3] == b"\x03\x03"

    # Test bit flipping
    buf.flip_bit(0, 0)
    assert buf.to_bytes()[0] == 0x17

    # Test byte replacement
    buf.replace_byte(1, 0xFF)
    assert buf.to_bytes()[1] == 0xFF

    # Test truncation
    buf.truncate(4)
    assert len(buf) == 4


def test_tls_record_builder_versions():
    # TLS 1.0
    ch_10 = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_0)
    assert ch_10[0] == TLSContentType.HANDSHAKE
    assert ch_10[1:3] == b"\x03\x01"

    # TLS 1.2
    ch_12 = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_2)
    assert ch_12[0] == TLSContentType.HANDSHAKE
    assert ch_12[1:3] == b"\x03\x03"

    # TLS 1.3: legacy_record_version is 0x0303
    ch_13 = TLSRecordBuilder.build_client_hello(target_version=TLSVersion.TLS_1_3)
    assert ch_13[0] == TLSContentType.HANDSHAKE
    assert ch_13[1:3] == b"\x03\x03"
    # Must include supported_versions (0x002B) and TLS 1.3 (0x0304)
    assert b"\x00\x2b" in ch_13
    assert b"\x03\x04" in ch_13


def test_tcp_stack_packet_generation():
    stack = UserSpaceTCPStack(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=50000,
        dst_port=443
    )

    # Standard packet
    pkt = stack.build_packet(flags="PA", payload=b"Hello")
    assert pkt["TCP"].flags == "PA"
    assert pkt["TCP"].sport == 50000
    assert pkt["TCP"].dport == 443

    # Mutated fields: Data offset, reserved, window, checksum override
    mutated = stack.build_packet(
        flags="S",
        seq=1234567,
        ack=7654321,
        data_offset=8,
        reserved=5,
        window=1024,
        chksum=0xDEAD,
        urgptr=12
    )
    assert mutated["TCP"].dataofs == 8
    assert mutated["TCP"].reserved == 5
    assert mutated["TCP"].window == 1024
    assert mutated["TCP"].chksum == 0xDEAD
    assert mutated["TCP"].urgptr == 12


def test_parse_ports():
    from client import parse_ports
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("8000-8003") == [8000, 8001, 8002, 8003]
    all_p = parse_ports("all")
    # 65535 minus excluded ports (22, 8765)
    assert len(all_p) == 65533
    assert 22 not in all_p
    assert 8765 not in all_p


def test_scenarios_count():
    assert len(ALL_TCP_SCENARIOS) == 20
    assert len(ALL_TLS_SCENARIOS) == 10
    assert len(ALL_COMBO_SCENARIOS) == 3

    total_per_dir = len(ALL_TCP_SCENARIOS) + len(ALL_TLS_SCENARIOS) + len(ALL_COMBO_SCENARIOS)
    assert total_per_dir == 33
    total_bidirectional = total_per_dir * 2
    assert total_bidirectional == 66


def test_html_report_generation(tmp_path):
    collector = ReportCollector()
    collector.add_result(TestResult(
        scenario_id="TCP-01",
        name="Standard Valid TCP Packet",
        category="TCP",
        field_tested="Standard Fields",
        original_val="RFC 793",
        mutated_val="RFC 793",
        direction="Client -> Server",
        attempts_used=1,
        rtt_ms=1.45,
        response_status="SUCCESS",
        peer_response_flags="A",
        details="Ack=100001, Seq=200000"
    ))
    collector.add_result(TestResult(
        scenario_id="TCP-06",
        name="Invalid Data Offset",
        category="TCP",
        field_tested="Data Offset",
        original_val="dataofs=5",
        mutated_val="dataofs=4",
        direction="Client -> Server",
        attempts_used=4,
        rtt_ms=2000.0,
        response_status="RETRY_EXHAUSTED",
        peer_response_flags="NONE",
        details="No response packet captured (Drop/Timeout)"
    ))

    summary = collector.get_summary()
    assert summary["total"] == 2
    assert summary["success"] == 1
    assert summary["retry_exhausted"] == 1

    report_file = tmp_path / "test_report.html"
    HTMLReportGenerator.generate(collector.results, summary, str(report_file))

    assert os.path.exists(report_file)
    content = report_file.read_text(encoding="utf-8")
    assert "NetProbe Protocol Test Report" in content
    assert "TCP-01" in content
    assert "TCP-06" in content
