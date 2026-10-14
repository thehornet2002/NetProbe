import sys
import os
import subprocess
import logging

logger = logging.getLogger("netprobe.firewall")


class FirewallGuard:
    """Manages automatic OS firewall rules to block kernel RST packets during raw socket tests."""

    def __init__(self, local_port: int = None, remote_ip: str = "127.0.0.1", remote_port: int = None):
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.is_linux = sys.platform.startswith("linux")
        self.is_windows = sys.platform.startswith("win")
        port_label = str(self.local_port) if self.local_port else "ALL"
        self.rule_name = f"NetProbe_Block_RST_{port_label}"
        self.applied = False

    def __enter__(self):
        self.apply()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.remove()

    def apply(self) -> bool:
        if self.applied:
            return True

        try:
            if self.is_linux:
                cmd = [
                    "iptables", "-A", "OUTPUT",
                    "-p", "tcp",
                    "--tcp-flags", "RST", "RST",
                    "-d", self.remote_ip,
                    "-j", "DROP"
                ]
                if self.local_port:
                    cmd.insert(6, "--sport")
                    cmd.insert(7, str(self.local_port))

                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    self.applied = True
                    logger.info(f"Linux iptables rule applied: port {self.local_port or 'ALL'} -> {self.remote_ip}")
                    return True
                else:
                    logger.warning(f"Failed to apply iptables rule (need sudo?): {res.stderr.strip()}")
            elif self.is_windows:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self.rule_name}",
                    "dir=out",
                    "action=block",
                    "protocol=TCP",
                    f"remoteip={self.remote_ip}"
                ]
                if self.local_port:
                    cmd.append(f"localport={self.local_port}")

                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    self.applied = True
                    logger.info(f"Windows firewall rule '{self.rule_name}' applied.")
                    return True
                else:
                    logger.warning(f"Failed to apply netsh rule (need Administrator?): {res.stderr.strip()}")
        except Exception as e:
            logger.warning(f"Error applying firewall rule: {e}")

        return False

    def remove(self) -> bool:
        if not self.applied:
            return True

        try:
            if self.is_linux:
                cmd = [
                    "iptables", "-D", "OUTPUT",
                    "-p", "tcp",
                    "--tcp-flags", "RST", "RST",
                    "-d", self.remote_ip,
                    "-j", "DROP"
                ]
                if self.local_port:
                    cmd.insert(6, "--sport")
                    cmd.insert(7, str(self.local_port))

                subprocess.run(cmd, capture_output=True, text=True)
                self.applied = False
                logger.info("Linux iptables rule removed.")
                return True
            elif self.is_windows:
                cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={self.rule_name}"
                ]
                subprocess.run(cmd, capture_output=True, text=True)
                self.applied = False
                logger.info(f"Windows firewall rule '{self.rule_name}' removed.")
                return True
        except Exception as e:
            logger.warning(f"Error removing firewall rule: {e}")

        return False
