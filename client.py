import argparse
import asyncio
import logging
import random
from typing import List, Set, Optional
from scapy.all import IP, TCP
from netprobe.core.firewall import FirewallGuard
from netprobe.core.pcap_engine import PcapEngine
from netprobe.core.tcp_stack import UserSpaceTCPStack
from netprobe.control.ws_client import ControlWSClient
from netprobe.control.protocol import MessageType
from netprobe.scenarios.base import TestResult
from netprobe.scenarios.tcp_scenarios import ALL_TCP_SCENARIOS
from netprobe.scenarios.tls_scenarios import ALL_TLS_SCENARIOS
from netprobe.scenarios.combo_scenarios import ALL_COMBO_SCENARIOS
from netprobe.report.collector import ReportCollector
from netprobe.report.html_generator import HTMLReportGenerator
import config

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netprobe.client")


def parse_ports(spec: str, exclude_ports: Set[int] = None) -> List[int]:
    """Parses port specification: 'all', '1-65535', '80,443', '9000-9010' excluding critical ports."""
    spec = spec.strip().lower()
    excluded = exclude_ports or {22, 8765}
    if spec == "all":
        return [p for p in range(1, 65536) if p not in excluded]
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports - excluded))


class NetProbeClient:
    def __init__(
        self,
        server_ip: str,
        client_ip: str,
        control_port: int,
        target_ports: List[int],
        client_port: int = 54321,
        iface: Optional[str] = None,
        output_report: str = "netprobe_report.html",
        scan_first: bool = True
    ):
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.control_port = control_port
        self.target_ports = target_ports
        self.client_port = client_port
        self.iface = iface
        self.output_report = output_report
        self.scan_first = scan_first

        self.ws_client = ControlWSClient(server_ip=server_ip, port=control_port)
        self.pcap = PcapEngine(iface=self.iface)
        self.collector = ReportCollector()
        self.server_finished_event = asyncio.Event()

    async def run(self):
        logger.info(f"Connecting to NetProbe Server at {self.server_ip}:{self.control_port}")
        connected = await self.ws_client.connect()
        if not connected:
            logger.error("Could not establish WebSocket control connection to server. Exiting.")
            return

        self.ws_client.on_message_callback = self._handle_control_message
        listen_task = asyncio.create_task(self.ws_client.listen())

        await self.ws_client.send(MessageType.HELLO, {
            "client_ip": self.client_ip,
            "client_port": self.client_port
        })

        fw_port = None if len(self.target_ports) > 1 else self.client_port
        with FirewallGuard(local_port=fw_port, remote_ip=self.server_ip):
            all_scenarios = ALL_TCP_SCENARIOS + ALL_TLS_SCENARIOS + ALL_COMBO_SCENARIOS
            ports_to_test = self.target_ports

            # If scanning large port ranges (e.g. all 65535), probe responsiveness first
            if self.scan_first and len(self.target_ports) > 100:
                logger.info(f"Initiating fast SYN probe across {len(self.target_ports)} ports...")
                responsive_ports = self._probe_responsive_ports(self.target_ports)
                logger.info(f"Discovered {len(responsive_ports)} responsive ports.")
                ports_to_test = responsive_ports if responsive_ports else self.target_ports[:10]

            print("=" * 60)
            print(" NETPROBE MULTI-PORT TEST ORCHESTRATOR ")
            print("=" * 60)
            print(f"Target Server:       {self.server_ip}")
            print(f"Target Ports:        {len(ports_to_test)} port(s)")
            print(f"Scenarios per Port:  {len(all_scenarios)}")
            print(f"Output Report:       {self.output_report}")
            print("=" * 60)

            # --- DIRECTION 1: Client -> Server ---
            logger.info(">>> STARTING DIRECTION 1: Client -> Server <<<")
            for port in ports_to_test:
                src_p = random.randint(30000, 60000)
                stack = UserSpaceTCPStack(
                    src_ip=self.client_ip,
                    dst_ip=self.server_ip,
                    src_port=src_p,
                    dst_port=port,
                    pcap_engine=self.pcap,
                    timeout=1.0
                )

                # 3-way handshake on port
                stack.client_handshake()

                for sc_factory in all_scenarios:
                    sc = sc_factory() if callable(sc_factory) else sc_factory
                    res = sc.execute(stack, direction=f"Client -> Server [Port {port}]")
                    self.collector.add_result(res)
                    await asyncio.sleep(0.01)

            # --- DIRECTION 2: Server -> Client ---
            logger.info(">>> STARTING DIRECTION 2: Server -> Client <<<")
            await self.ws_client.send("RUN_SERVER_TO_CLIENT", {"ports": ports_to_test})
            await self.server_finished_event.wait()

        await self.ws_client.close()
        listen_task.cancel()

        summary = self.collector.get_summary()
        report_file = HTMLReportGenerator.generate(self.collector.results, summary, self.output_report)

        print("\n" + "=" * 60)
        print(" TEST EXECUTION SUMMARY ")
        print("=" * 60)
        print(f"Total Tests Executed: {summary['total']}")
        print(f"Successful Responses: {summary['success']}")
        print(f"Rejected with RST:    {summary['rejected_rst']}")
        print(f"Retries Exhausted:    {summary['retry_exhausted']}")
        print(f"Average Delay (RTT):  {summary['avg_rtt_ms']} ms")
        print(f"HTML Report Saved:    {report_file}")
        print("=" * 60)

    def _probe_responsive_ports(self, port_list: List[int]) -> List[int]:
        """Probes ports with raw SYN packets to filter active listeners."""
        active = []
        for port in port_list:
            sport = random.randint(40000, 60000)
            syn = IP(src=self.client_ip, dst=self.server_ip) / TCP(sport=sport, dport=port, flags="S", seq=1000)
            self.pcap.send_packet(syn)
            resp = self.pcap.sniff_one(
                bpf_filter=f"tcp and src host {self.server_ip} and src port {port} and dst port {sport}",
                timeout=0.08
            )
            if resp and resp.haslayer(TCP):
                active.append(port)
                self.collector.add_result(TestResult(
                    scenario_id=f"SYN-PROBE-{port}",
                    name=f"Port {port} SYN Probe",
                    category="PORT_DISCOVERY",
                    field_tested="SYN Flag",
                    original_val="CLOSED",
                    mutated_val="OPEN/LISTENING",
                    direction=f"Client -> Server [Port {port}]",
                    attempts_used=1,
                    rtt_ms=1.5,
                    response_status="SUCCESS",
                    peer_response_flags=str(resp[TCP].flags),
                    details=f"Port {port} responded with flags {resp[TCP].flags}"
                ))
        return active

    async def _handle_control_message(self, msg: dict):
        mtype = msg.get("type")
        payload = msg.get("payload", {})

        if mtype == MessageType.RESULT:
            res = TestResult(**payload)
            self.collector.add_result(res)

        elif mtype == MessageType.FINISHED:
            logger.info("Server reported completion of Server -> Client testing.")
            self.server_finished_event.set()


def main():
    parser = argparse.ArgumentParser(description="NetProbe Multi-Port Windows Client")
    parser.add_argument("--server-ip", default=config.DEFAULT_SERVER_IP, help="Target Linux Server IP")
    parser.add_argument("--client-ip", default=config.DEFAULT_CLIENT_IP, help="Local Windows Client IP")
    parser.add_argument("--control-port", type=int, default=config.DEFAULT_CONTROL_PORT, help="WebSocket Control Port")
    parser.add_argument("--ports", default="all", help="Target ports: 'all', '1-65535', '80,443', or single port")
    parser.add_argument("--client-port", type=int, default=54321, help="Client Raw Test Port")
    parser.add_argument("--iface", default=None, help="Network Interface Name")
    parser.add_argument("--output", default="netprobe_report.html", help="Path to generate HTML report")
    parser.add_argument("--no-scan-first", action="store_true", help="Force running all scenarios on all ports without initial SYN probe")

    args = parser.parse_args()
    ports = parse_ports(args.ports, exclude_ports={22, args.control_port})

    client = NetProbeClient(
        server_ip=args.server_ip,
        client_ip=args.client_ip,
        control_port=args.control_port,
        target_ports=ports,
        client_port=args.client_port,
        iface=args.iface,
        output_report=args.output,
        scan_first=not args.no_scan_first
    )

    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        logger.info("Client execution interrupted.")


if __name__ == "__main__":
    main()
