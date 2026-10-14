import time
import random
import logging
from typing import Optional, Dict, Any, Tuple, List
from scapy.all import IP, TCP, Raw
from netprobe.core.pcap_engine import PcapEngine

logger = logging.getLogger("netprobe.tcp_stack")


class TCPState:
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    RESET = "RESET"


class UserSpaceTCPStack:
    """A user-space TCP stack capable of raw bit-level packet injection,

    state tracking, RTT calculation, and retry enforcement (max 4).
    """

    MAX_RETRIES = 4

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        pcap_engine: Optional[PcapEngine] = None,
        timeout: float = 2.0
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.pcap = pcap_engine or PcapEngine()
        self.timeout = timeout

        self.seq = random.randint(10000, 500000)
        self.ack = 0
        self.peer_seq = 0
        self.peer_ack = 0
        self.state = TCPState.CLOSED
        self.window = 64240

    @property
    def bpf_incoming(self) -> str:
        return f"tcp and src host {self.dst_ip} and src port {self.dst_port} and dst port {self.src_port}"

    def build_packet(
        self,
        flags: str = "A",
        seq: Optional[int] = None,
        ack: Optional[int] = None,
        data_offset: Optional[int] = None,
        reserved: Optional[int] = None,
        window: Optional[int] = None,
        chksum: Optional[int] = None,
        urgptr: Optional[int] = None,
        options: Optional[List] = None,
        payload: bytes = b""
    ) -> IP:
        """Constructs an IP/TCP packet with optional bit-level field overrides."""
        actual_seq = self.seq if seq is None else seq
        actual_ack = self.ack if ack is None else ack
        actual_win = self.window if window is None else window

        tcp_kwargs: Dict[str, Any] = {
            "sport": self.src_port,
            "dport": self.dst_port,
            "seq": actual_seq,
            "ack": actual_ack,
            "flags": flags,
            "window": actual_win,
        }

        if data_offset is not None:
            tcp_kwargs["dataofs"] = data_offset
        if reserved is not None:
            tcp_kwargs["reserved"] = reserved
        if chksum is not None:
            tcp_kwargs["chksum"] = chksum
        if urgptr is not None:
            tcp_kwargs["urgptr"] = urgptr
        if options is not None:
            tcp_kwargs["options"] = options

        tcp_layer = TCP(**tcp_kwargs)
        ip_layer = IP(src=self.src_ip, dst=self.dst_ip)
        pkt = ip_layer / tcp_layer

        if payload:
            pkt = pkt / Raw(load=payload)

        return pkt

    def send_and_wait_response(
        self,
        pkt: IP,
        custom_bpf: Optional[str] = None,
        timeout: Optional[float] = None,
        max_retries: int = MAX_RETRIES
    ) -> Tuple[Optional[Any], float, int, str]:
        """Sends a packet with up to `max_retries` attempts.

        Returns: (response_pkt, delay_ms, attempts_used, status_str)
        """
        bpf = custom_bpf or self.bpf_incoming
        wait_time = timeout or self.timeout

        for attempt in range(1, max_retries + 1):
            t_start = time.perf_counter()
            self.pcap.send_packet(pkt)
            resp = self.pcap.sniff_one(bpf_filter=bpf, timeout=wait_time)
            t_end = time.perf_counter()
            delay_ms = (t_end - t_start) * 1000.0

            if resp is not None and resp.haslayer(TCP):
                tcp_resp = resp[TCP]
                status = "SUCCESS"
                if "R" in tcp_resp.flags:
                    status = "REJECTED_RST"
                elif "F" in tcp_resp.flags:
                    status = "PEER_FIN"

                # Update internal state tracking
                self.peer_seq = tcp_resp.seq
                self.peer_ack = tcp_resp.ack
                return resp, delay_ms, attempt, status

            logger.debug(f"Attempt {attempt}/{max_retries} timed out for dst {self.dst_ip}:{self.dst_port}")

        return None, (wait_time * 1000.0), max_retries, "RETRY_EXHAUSTED"

    def client_handshake(self) -> Tuple[bool, Dict[str, Any]]:
        """Executes a 3-way TCP handshake in user space.

        Client -> SYN -> Server
        Server -> SYN-ACK -> Client
        Client -> ACK -> Server
        """
        self.seq = random.randint(10000, 500000)
        syn_pkt = self.build_packet(flags="S", seq=self.seq, ack=0)
        self.state = TCPState.SYN_SENT

        resp, delay_ms, attempts, status = self.send_and_wait_response(syn_pkt)
        if not resp or not resp.haslayer(TCP):
            self.state = TCPState.CLOSED
            return False, {
                "handshake": "FAILED",
                "reason": status,
                "delay_ms": delay_ms,
                "attempts": attempts
            }

        tcp_resp = resp[TCP]
        if "S" in tcp_resp.flags and "A" in tcp_resp.flags:
            self.peer_seq = tcp_resp.seq
            self.ack = tcp_resp.seq + 1
            self.seq += 1

            # Send final ACK
            ack_pkt = self.build_packet(flags="A", seq=self.seq, ack=self.ack)
            self.pcap.send_packet(ack_pkt)
            self.state = TCPState.ESTABLISHED
            return True, {
                "handshake": "ESTABLISHED",
                "rtt_ms": delay_ms,
                "server_seq": self.peer_seq,
                "client_seq": self.seq,
                "attempts": attempts
            }

        self.state = TCPState.CLOSED
        return False, {
            "handshake": "FAILED",
            "reason": f"Unexpected flags: {tcp_resp.flags}",
            "delay_ms": delay_ms,
            "attempts": attempts
        }

    def close(self):
        """Gracefully closes connection with FIN/RST."""
        if self.state == TCPState.ESTABLISHED:
            fin_pkt = self.build_packet(flags="FA", seq=self.seq, ack=self.ack)
            self.pcap.send_packet(fin_pkt)
        self.state = TCPState.CLOSED
