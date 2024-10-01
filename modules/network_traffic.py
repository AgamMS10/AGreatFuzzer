# modules/network_traffic.py

import os

from . import utils


class NetworkTrafficMonitor:
    def __init__(self, pid):
        self.pid = pid
        self.prev_stats = None

    def get_network_stats(self):
        net_dev_path = f"/proc/{self.pid}/net/dev"
        stats = {}

        if not os.path.exists(net_dev_path):
            print(f"Network statistics not available for PID {self.pid}.")
            return stats

        try:
            with open(net_dev_path, "r") as f:
                data = f.readlines()
        except Exception as e:
            print(f"Error reading {net_dev_path}: {e}")
            return stats

        # Parse the data
        for line in data[2:]:
            line = line.strip()
            if not line:
                continue
            interface, stats_line = line.split(":", 1)
            stats_values = stats_line.strip().split()
            bytes_received = int(stats_values[0])
            bytes_transmitted = int(stats_values[8])
            stats[interface.strip()] = {
                "bytes_received": bytes_received,
                "bytes_transmitted": bytes_transmitted,
            }
        return stats

    def display_network_traffic(self, interval):
        curr_stats = self.get_network_stats()
        if not curr_stats:
            return

        print("Network Traffic:")
        print(
            f"{'Interface':<10} {'Bytes Received':<15} {'Bytes Transmitted':<18} {'Rx Rate':<15} {'Tx Rate':<15}"
        )
        print("-" * 80)
        for interface, data in curr_stats.items():
            bytes_received_formatted = utils.format_bytes(data["bytes_received"])
            bytes_transmitted_formatted = utils.format_bytes(data["bytes_transmitted"])

            rx_rate = "-"
            tx_rate = "-"
            if self.prev_stats and interface in self.prev_stats:
                rx_diff = (
                    data["bytes_received"]
                    - self.prev_stats[interface]["bytes_received"]
                )
                tx_diff = (
                    data["bytes_transmitted"]
                    - self.prev_stats[interface]["bytes_transmitted"]
                )
                rx_rate_value = rx_diff / interval
                tx_rate_value = tx_diff / interval
                rx_rate = utils.format_bytes(rx_rate_value) + "/s"
                tx_rate = utils.format_bytes(tx_rate_value) + "/s"

            print(
                f"{interface:<10} {bytes_received_formatted:<15} {bytes_transmitted_formatted:<18} {rx_rate:<15} {tx_rate:<15}"
            )

        print("\n")
        self.prev_stats = curr_stats
