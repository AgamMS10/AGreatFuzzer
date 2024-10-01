# modules/active_ports.py

import os


class ActivePortsMonitor:
    def __init__(self, pid):
        self.pid = pid

    def get_active_ports(self):
        ports = set()
        net_tcp_path = f"/proc/{self.pid}/net/tcp"
        net_udp_path = f"/proc/{self.pid}/net/udp"

        for path in [net_tcp_path, net_udp_path]:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r") as f:
                    data = f.readlines()
            except Exception as e:
                print(f"Error reading {path}: {e}")
                continue

            for line in data[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                local_address = parts[1]
                port_hex = local_address.split(":")[1]
                port = int(port_hex, 16)
                ports.add(port)
        return ports

    def display_active_ports(self):
        ports = self.get_active_ports()
        if not ports:
            print("No active ports.")
            return

        print("Active Ports:")
        print(", ".join(str(port) for port in sorted(ports)))
        print("\n")
