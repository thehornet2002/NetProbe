import time
import logging
from typing import Optional, Callable
from scapy.all import IP, TCP, Raw, send, sniff, AsyncSniffer, conf

logger = logging.getLogger("netprobe.pcap")

# Use native L3 or L2 socket where appropriate
conf.verb = 0


class PcapEngine:
    """Handles raw packet injection and sniffing using pcap/npcap via Scapy."""

    def __init__(self, iface: Optional[str] = None):
        self.iface = iface
        self.sniffer: Optional[AsyncSniffer] = None

    def send_packet(self, pkt, iface: Optional[str] = None) -> float:
        """Sends a packet and returns the dispatch timestamp."""
        t_sent = time.perf_counter()
        target_iface = iface or self.iface
        send(pkt, iface=target_iface, verbose=False)
        return t_sent

    def start_capture(self, bpf_filter: str, prn: Optional[Callable] = None, timeout: Optional[int] = None) -> AsyncSniffer:
        """Starts asynchronous packet capture with the specified BPF filter."""
        self.sniffer = AsyncSniffer(
            filter=bpf_filter,
            prn=prn,
            iface=self.iface,
            timeout=timeout,
            store=True
        )
        self.sniffer.start()
        return self.sniffer

    def stop_capture(self):
        """Stops the active sniffer and returns captured packets."""
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
            return self.sniffer.results
        return []

    def sniff_one(self, bpf_filter: str, timeout: float = 2.0):
        """Sniffs a single packet matching filter within timeout."""
        pkts = sniff(
            filter=bpf_filter,
            iface=self.iface,
            count=1,
            timeout=timeout,
            store=True
        )
        if pkts and len(pkts) > 0:
            return pkts[0]
        return None
