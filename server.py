import argparse
import asyncio
import logging
from typing import List, Set, Optional
from scapy.all import IP, TCP
from netprobe.core.firewall import FirewallGuard
from netprobe.core.pcap_engine import PcapEngine
from netprobe.core.tcp_stack import UserSpaceTCPStack
from netprobe.control.ws_server import ControlWSServer
from netprobe.control.protocol import MessageType
from netprobe.scenarios.tcp_scenarios import ALL_TCP_SCENARIOS
from netprobe.scenarios.tls_scenarios import ALL_TLS_SCENARIOS
from netprobe.scenarios.combo_scenarios import ALL_COMBO_SCENARIOS
import config

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("netprobe.server")


def parse_ports(spec: str) -> List[int]:
    """Parses port specification: 'all', '1-65535', '80,443', '9000-9010'."""
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(1, 65536))
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
    return sorted(list(ports))


class NetProbeServer:
    def __init__(self, bind_ip: str, client_ip: str, control_port: int, ports: List[int], iface: Optional[str] = None):
        self.bind_ip = bind_ip
        self.client_ip = client_ip
        self.control_port = control_port
        self.target_ports: Set[int] = set(ports)
        self.iface = iface
        self.ws_server = ControlWSServer(host="0.0.0.0", port=control_port)
        self.pcap = PcapEngine(iface=self.iface)
        self.running = True

    async def run(self):
        ports_desc = "ALL (1-65535)" if len(self.target_ports) >= 65535 else f"{len(self.target_ports)} ports"
        logger.info(f"Starting NetProbe Linux Server. Listening on {ports_desc}, Client IP: {self.client_ip}")

        # Block kernel RST across tested ports to prevent OS kernel interference
        fw_port = None if len(self.target_ports) > 1 else next(iter(self.target_ports))
        with FirewallGuard(local_port=fw_port, remote_ip=self.client_ip):
            self.ws_server.on_message_callback = self._handle_control_message
            await self.ws_server.start()

            responder_task = asyncio.create_task(self._passive_responder_loop())

            try:
                while self.running:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                pass
            finally:
                responder_task.cancel()
                await self.ws_server.stop()

    async def _passive_responder_loop(self):
        """Passively answers incoming SYN or test packets with standard TCP responses across all configured ports."""
        bpf = f"tcp and src host {self.client_ip}"
        logger.info(f"Server passive responder active on BPF: {bpf}")

        loop = asyncio.get_running_loop()

        def sniff_and_respond():
            pkt = self.pcap.sniff_one(bpf_filter=bpf, timeout=0.5)
            if pkt and pkt.haslayer(TCP):
                tcp = pkt[TCP]
                dst_p = tcp.dport
                src_p = tcp.sport

                if len(self.target_ports) < 65535 and dst_p not in self.target_ports:
                    return

                # If client sent SYN, respond with SYN-ACK from that specific port
                if "S" in tcp.flags and "A" not in tcp.flags:
                    syn_ack = IP(src=self.bind_ip, dst=self.client_ip) / TCP(
                        sport=dst_p,
                        dport=src_p,
                        seq=100000,
                        ack=tcp.seq + 1,
                        flags="SA"
                    )
                    self.pcap.send_packet(syn_ack)
                elif "P" in tcp.flags or ("A" in tcp.flags and bytes(tcp.payload)):
                    # Acknowledge data packet
                    ack_pkt = IP(src=self.bind_ip, dst=self.client_ip) / TCP(
                        sport=dst_p,
                        dport=src_p,
                        seq=100001,
                        ack=tcp.seq + max(1, len(bytes(tcp.payload))),
                        flags="A"
                    )
                    self.pcap.send_packet(ack_pkt)

        while self.running:
            await loop.run_in_executor(None, sniff_and_respond)
            await asyncio.sleep(0.005)

    async def _handle_control_message(self, msg: dict):
        mtype = msg.get("type")
        payload = msg.get("payload", {})

        if mtype == MessageType.HELLO:
            logger.info(f"Received HELLO from client: {payload}")
            await self.ws_server.send(MessageType.HELLO_ACK, {"status": "READY", "server_ip": self.bind_ip})

        elif mtype == "RUN_SERVER_TO_CLIENT":
            target_ports = payload.get("ports", [payload.get("client_port", 54321)])
            logger.info(f"Triggering test execution: Server -> Client on {len(target_ports)} ports")
            await self._run_server_to_client_tests(target_ports)

    async def _run_server_to_client_tests(self, target_ports: List[int]):
        all_scenarios = ALL_TCP_SCENARIOS + ALL_TLS_SCENARIOS + ALL_COMBO_SCENARIOS

        for dport in target_ports:
            sport = 9443 if dport != 9443 else 9444
            stack = UserSpaceTCPStack(
                src_ip=self.bind_ip,
                dst_ip=self.client_ip,
                src_port=sport,
                dst_port=dport,
                pcap_engine=self.pcap
            )

            for sc_factory in all_scenarios:
                sc = sc_factory() if callable(sc_factory) else sc_factory
                res = sc.execute(stack, direction=f"Server -> Client [Port {dport}]")
                await self.ws_server.send(MessageType.RESULT, res.to_dict())
                await asyncio.sleep(0.02)

        await self.ws_server.send(MessageType.FINISHED, {"direction": "Server -> Client"})


def main():
    parser = argparse.ArgumentParser(description="NetProbe Multi-Port Linux Server")
    parser.add_argument("--bind-ip", default=config.DEFAULT_SERVER_IP, help="Server IP address")
    parser.add_argument("--client-ip", default=config.DEFAULT_CLIENT_IP, help="Target Windows Client IP")
    parser.add_argument("--control-port", type=int, default=config.DEFAULT_CONTROL_PORT, help="WebSocket Control Port")
    parser.add_argument("--ports", default="all", help="Target test ports: 'all', '1-65535', '80,443', or single port")
    parser.add_argument("--iface", default=None, help="Network Interface Name")

    args = parser.parse_args()
    ports = parse_ports(args.ports)

    server = NetProbeServer(
        bind_ip=args.bind_ip,
        client_ip=args.client_ip,
        control_port=args.control_port,
        ports=ports,
        iface=args.iface
    )

    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Server shutting down.")


if __name__ == "__main__":
    main()
