# modules/network_monitor.py

import os
import socket
import time

import psutil

from modules.utils import clear_screen

from . import utils


class NetworkTrafficMonitor:
    def __init__(self):
        self.prev_stats = None

    def prompt_for_parameters(self):
        interface = input("Enter the interface name: ")
        interval = int(input("Enter the interval in seconds: "))
        return interface, interval

    def check_interface(self, interface):
        # Use psutil to verify that the interface exists.
        if interface not in psutil.net_if_stats():
            print(f"Interface '{interface}' does not exist.")
            return False
        return True

    def scan_interfaces(self):
        # List available interfaces using psutil.
        interfaces = list(psutil.net_io_counters(pernic=True).keys())
        print("Available Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        print()

    def get_network_stats(self, interface):
        counters = psutil.net_io_counters(pernic=True)
        if interface in counters:
            return counters[interface]._asdict()
        else:
            print(f"Interface '{interface}' not found.")
            return None

    def get_active_connections(self, interface):
        """
        Returns a list of active network connections whose local IP address belongs
        to the selected interface.
        """
        # Get all IP addresses assigned to the interface.
        if_addrs = psutil.net_if_addrs().get(interface, [])
        ip_addresses = [
            addr.address
            for addr in if_addrs
            if addr.family in (socket.AF_INET, socket.AF_INET6)
        ]

        # Get all inet connections and filter by those with a local IP in ip_addresses.
        conns = psutil.net_connections(kind="inet")
        active_conns = []
        for conn in conns:
            if conn.laddr:
                local_ip = conn.laddr[0]  # laddr is typically a tuple (ip, port)
                if local_ip in ip_addresses:
                    active_conns.append(conn)
        return active_conns

    def display_network_traffic(self, interface, curr_stats, interval):
        """
        Displays a formatted layout showing RX and TX statistics along with packets,
        errors, and dropped counts. It computes rates if previous statistics exist.
        """
        # Compute rates if previous data exists.
        if self.prev_stats:
            rx_rate = (
                curr_stats["bytes_recv"] - self.prev_stats["bytes_recv"]
            ) / interval
            tx_rate = (
                curr_stats["bytes_sent"] - self.prev_stats["bytes_sent"]
            ) / interval
        else:
            rx_rate = tx_rate = 0

        header_line = "=" * 70
        print(header_line)
        print(f"Network Interface: {interface}")
        print(header_line)
        # Header for RX / TX columns.
        print(f"{'':<15}{'RX':^25}{'TX':^25}")
        print("-" * 70)
        # Bytes (with rates)
        print(
            f"{'Bytes':<15}"
            f"{utils.format_bytes(curr_stats['bytes_recv'])} ({utils.format_bytes(rx_rate)}/s)"
            f"{'':>5}{utils.format_bytes(curr_stats['bytes_sent'])} ({utils.format_bytes(tx_rate)}/s)"
        )
        # Packets
        print(
            f"{'Packets':<15}{str(curr_stats['packets_recv']):<25}{str(curr_stats['packets_sent']):<25}"
        )
        # Errors
        print(
            f"{'Errors':<15}{str(curr_stats['errin']):<25}{str(curr_stats['errout']):<25}"
        )
        # Dropped
        print(
            f"{'Dropped':<15}{str(curr_stats['dropin']):<25}{str(curr_stats['dropout']):<25}"
        )
        print(header_line)

    def display_active_connections(self, interface):
        """
        Displays a table of active connections (ports) on the selected interface.
        """
        active_conns = self.get_active_connections(interface)
        print("\nActive Connections on Interface:", interface)
        print("-" * 90)
        print(
            f"{'Local Port':<12}{'Remote Address':<22}{'Remote Port':<12}{'Status':<12}{'PID':<8}{'Process Name':<15}"
        )
        print("-" * 90)
        if not active_conns:
            print("No active connections.")
        else:
            for conn in active_conns:
                # laddr is a tuple: (ip, port)
                local_port = conn.laddr[1] if len(conn.laddr) > 1 else "-"
                # raddr may be empty if not connected.
                if conn.raddr:
                    remote_ip = conn.raddr[0]
                    remote_port = conn.raddr[1] if len(conn.raddr) > 1 else "-"
                else:
                    remote_ip = "-"
                    remote_port = "-"
                status = conn.status
                pid = conn.pid if conn.pid is not None else "-"
                proc_name = "-"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                    except Exception:
                        proc_name = "N/A"
                print(
                    f"{local_port:<12}{remote_ip:<22}{remote_port:<12}{status:<12}{pid:<8}{proc_name:<15}"
                )
        print("-" * 90)

    def run(self):
        try:

            self.scan_interfaces()
            interface, interval = self.prompt_for_parameters()

            if not self.check_interface(interface):
                return

            while True:
                curr_stats = self.get_network_stats(interface)
                if curr_stats is None:
                    break

                # Clear the screen so the display updates in place.
                clear_screen()
                self.display_network_traffic(interface, curr_stats, interval)
                self.display_active_connections(interface)
                self.prev_stats = curr_stats

                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()
