# modules/connections.py

import os
import socket
from dataclasses import dataclass

from . import utils


@dataclass
class Connection:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int = None


class ConnectionsMonitor:
    def __init__(self, pid):
        self.pid = pid

    def get_active_connections(self):
        connections = []
        protocols = ["tcp", "udp", "icmp"]
        # Include IPv6 versions if desired
        # protocols.extend(['tcp6', 'udp6', 'icmp6'])

        for proto in protocols:
            path = f"/proc/{self.pid}/net/{proto}"
            if not os.path.exists(path):
                continue
            conns = self.parse_net_file(path, proto)
            connections.extend(conns)
        return connections

    def parse_net_file(self, path, protocol):
        try:
            with open(path, "r") as f:
                content = f.readlines()
        except Exception as e:
            print(f"Error reading {path}: {e}")
            return []

        connections = []
        for line in content[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            local_address = parts[1]
            remote_address = parts[2]

            if protocol == "tcp":
                state = parts[3]
                state_str = utils.tcp_state(state)
            elif protocol == "icmp":
                icmp_type, icmp_code = self.parse_icmp_type_code(parts[3])
                state_str = f"Type:{icmp_type} Code:{icmp_code}"
            else:
                state_str = "N/A"

            local_ip, local_port = utils.parse_address(local_address)
            remote_ip, remote_port = utils.parse_address(remote_address)

            connections.append(
                Connection(
                    protocol=protocol.upper(),
                    local_address=local_ip,
                    local_port=local_port,
                    remote_address=remote_ip,
                    remote_port=remote_port,
                    state=state_str,
                )
            )
        return connections

    def display_connections(self):
        connections = self.get_active_connections()
        if not connections:
            print("No active connections.")
            return

        print("Active Connections:")
        print(
            f"{'Proto':<6} {'Local Address':<22} {'Remote Address':<22} {'State':<20} {'Service':<10}"
        )
        print("-" * 90)
        for conn in connections:
            service = self.get_service_name(
                conn.local_port, conn.remote_port, conn.protocol
            )
            local = f"{conn.local_address}:{conn.local_port}"
            remote = f"{conn.remote_address}:{conn.remote_port}"
            print(
                f"{conn.protocol:<6} {local:<22} {remote:<22} {conn.state:<20} {service:<10}"
            )
        print("\n")

    def get_service_name(self, local_port, remote_port, protocol):
        try:
            service_name = socket.getservbyport(local_port, protocol.lower())
            return service_name.upper()
        except:
            try:
                service_name = socket.getservbyport(remote_port, protocol.lower())
                return service_name.upper()
            except:
                return ""

    def parse_icmp_type_code(self, hex_value):
        # ICMP type and code are stored in a single hex value
        # Since ICMP doesn't use ports, we parse the hex value to get type and code
        icmp_type = int(hex_value[:2], 16)
        icmp_code = int(hex_value[2:4], 16)
        return icmp_type, icmp_code
