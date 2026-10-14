import random
from netprobe.scenarios.base import TestResult
from netprobe.scenarios.tcp_scenarios import ALL_TCP_SCENARIOS
from netprobe.scenarios.tls_scenarios import ALL_TLS_SCENARIOS
from netprobe.scenarios.combo_scenarios import ALL_COMBO_SCENARIOS
from netprobe.report.collector import ReportCollector
from netprobe.report.html_generator import HTMLReportGenerator


def generate_sample_report(output_file: str = "netprobe_report.html"):
    collector = ReportCollector()
    all_scenarios = ALL_TCP_SCENARIOS + ALL_TLS_SCENARIOS + ALL_COMBO_SCENARIOS

    for direction in ["Client -> Server", "Server -> Client"]:
        for sc_factory in all_scenarios:
            sc = sc_factory() if callable(sc_factory) else sc_factory
            attempts = 1 if "Standard" in sc.name else random.choices([1, 2, 4], weights=[0.7, 0.2, 0.1])[0]
            rtt = round(random.uniform(0.8, 4.5), 2)
            
            if "Checksum" in sc.name or "Corrupt" in sc.name or "Truncated" in sc.name:
                status = "RETRY_EXHAUSTED"
                flags = "NONE"
                details = "Packet silently dropped by target stack (Timeout after 4 attempts)"
                rtt = 2000.0
                attempts = 4
            elif "RST" in sc.name or "Invalid" in sc.name or "Offset" in sc.name:
                status = "REJECTED_RST"
                flags = "R"
                details = "Target TCP stack rejected invalid packet with RST flag"
            else:
                status = "SUCCESS"
                flags = "A" if "TCP" in sc.category else "PA"
                details = f"Normal ACK received, Window=64240, Ack incremented"

            res = TestResult(
                scenario_id=sc.scenario_id,
                name=sc.name,
                category=sc.category,
                field_tested=sc.field_tested,
                original_val="RFC Standard Compliant",
                mutated_val="Bit/Byte Modified Value",
                direction=direction,
                attempts_used=attempts,
                rtt_ms=rtt,
                response_status=status,
                peer_response_flags=flags,
                details=details
            )
            collector.add_result(res)

    summary = collector.get_summary()
    HTMLReportGenerator.generate(collector.results, summary, output_file)
    print(f"Sample report generated: {output_file} with {summary['total']} scenarios.")


if __name__ == "__main__":
    generate_sample_report()
