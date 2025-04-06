# modules/scanner.py

import os
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep

import nmap

from modules import utils


class Scanner:
    def __init__(self, target=None, verbose=True):
        self.verbose = verbose
        self.target = target if target else utils.get_target_ip(logger=self.log)
        self.scan_results = {}

    def log(self, message):
        if self.verbose:
            print(message)

    def scan_udp_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(b"", (self.target, port))
            try:
                data, _ = s.recvfrom(1024)
                return port, "open"
            except socket.timeout:
                return port, "Timeout"
        except Exception:
            return port, None
        finally:
            s.close()

    def scan_tcp_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            result = s.connect_ex((self.target, port))
            if result == 0:
                return port, "open"
            else:
                return port, None
        except Exception:
            return port, None
        finally:
            s.close()

    def scan_ports(self):
        """
        Open port scan for TCP and UDP ports 0-1023.
        Returns a dictionary with TCP and UDP scan results.
        """
        self.log("Starting open port scan on TCP and UDP ports 0-1023...")
        results = {"tcp": {}, "udp": {}}

        with ThreadPoolExecutor(max_workers=100) as executor:
            tcp_futures = {
                executor.submit(self.scan_tcp_port, port): port
                for port in range(0, 1024)
            }
            udp_futures = {
                executor.submit(self.scan_udp_port, port): port
                for port in range(0, 1024)
            }

            for future in as_completed(tcp_futures):
                port, status = future.result()
                if status:
                    results["tcp"][port] = status

            for future in as_completed(udp_futures):
                port, status = future.result()
                if status:
                    results["udp"][port] = status

        self.scan_results["open_port_scan"] = results
        self.log("Open port scan completed.")
        return results

    def custom_port_range_scan(self):
        """
        Scans a user provided custom port range for open TCP and UDP ports.
        Returns a dictionary with TCP and UDP scan results for the specified range.
        """
        port_range = input("Enter custom port range (e.g., 20-80): ").strip()
        try:
            start_port, end_port = map(int, port_range.split("-"))
        except Exception:
            self.log("Invalid port range format. Use 'start-end' (e.g., 20-80).")
            return None

        self.log(
            f"Starting custom port range scan for ports {start_port} to {end_port}..."
        )
        results = {"tcp": {}, "udp": {}}
        with ThreadPoolExecutor(max_workers=100) as executor:
            tcp_futures = {
                executor.submit(self.scan_tcp_port, port): port
                for port in range(start_port, end_port + 1)
            }
            udp_futures = {
                executor.submit(self.scan_udp_port, port): port
                for port in range(start_port, end_port + 1)
            }

            for future in as_completed(tcp_futures):
                port, status = future.result()
                if status:
                    results["tcp"][port] = status

            for future in as_completed(udp_futures):
                port, status = future.result()
                if status:
                    results["udp"][port] = status

        self.scan_results["custom_port_scan"] = results
        self.log("Custom port range scan completed.")
        return results

    def service_scan(self):
        """
        Performs a detailed scan for services and versions on the target machine using nmap.
        Returns the nmap scan result as a dictionary.
        """
        self.log("Starting service scan using nmap (-sV)...")
        nm = nmap.PortScanner()
        try:
            nm.scan(self.target, arguments="-sV")
            results = nm[self.target]
            self.scan_results["service_scan"] = results
            self.log("Service scan completed.")
            return results
        except Exception as e:
            self.log(f"Error during service scan: {e}")
            return None

    def log_results_to_file(self, filename="scan_results.log"):
        import json

        try:
            with open(filename, "w") as f:
                json.dump(self.scan_results, f, indent=4)
            self.log(f"Scan results successfully logged to {filename}")
        except Exception as e:
            self.log(f"Failed to log scan results to file: {e}")

    def run(self):
        menu = """
Select an option:
1. Open port scan (TCP and UDP ports 0-1023)
2. Sevices scan (nmap)
3. Custom port range scan
4. Log results to file
5. Exit
"""
        while True:
            print(menu)
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                self.scan_ports()
            elif choice == "2":
                self.service_scan()
            elif choice == "3":
                self.custom_port_range_scan()
            elif choice == "4":
                self.log_results_to_file()
            elif choice == "5":
                self.log("Exiting...")
                break
            else:
                self.log("Invalid choice. Please try again.")
            sleep(1)
