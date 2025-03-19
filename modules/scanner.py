# modules/scanner.py

import os
import platform
import socket
import subprocess
from time import sleep

import nmap

from modules import utils


class Scanner:
    def __init__(self, target=None, verbose=True):
        self.target = target if target else self.get_target_ip()
        self.verbose = verbose
        self.scan_results = {}

    def log(self, message):
        if self.verbose:
            print(message)

    def get_target_ip(self) -> str:
        try:
            selection = (
                input(
                    "Select target selection method ('manual' for manual input or 'nmap' to scan network): "
                )
                .strip()
                .lower()
            )
            if selection == "manual":
                return utils.get_ip_address()
            elif selection == "nmap":
                network_range = utils.get_network_range()
                self.log(f"Scanning network range: {network_range}")
                available_ips = utils.scan_network(network_range)
                if not available_ips:
                    self.log("No available IP addresses found. Please try again.")
                    return self.get_target_ip()
                self.log("\nAvailable IP addresses:")
                for idx, ip in enumerate(available_ips, start=1):
                    self.log(f"{idx}. {ip}")
                choice = input("Select an IP by entering its number: ").strip()
                try:
                    index = int(choice) - 1
                    if index < 0 or index >= len(available_ips):
                        self.log("Invalid selection. Please try again.")
                        return self.get_target_ip()
                    return available_ips[index]
                except ValueError:
                    self.log("Invalid input. Please enter a valid number.")
                    return self.get_target_ip()
            else:
                self.log("Invalid selection. Please type 'manual' or 'nmap'.")
                return self.get_target_ip()
        except KeyboardInterrupt:
            self.log("\nExiting....")
            exit()

    def scan_ports(self):
        nm = nmap.PortScanner()
        nm.scan(self.target, "0-1023", arguments="-sS -sU")

        results = {}
        if self.target in nm.all_hosts():
            results[self.target] = {
                "hostname": nm[self.target].hostname(),
                "state": nm[self.target].state(),
                "protocols": {},
            }
            for proto in nm[self.target].all_protocols():
                results[self.target]["protocols"][proto] = {}
                for port in sorted(nm[self.target][proto].keys()):
                    results[self.target]["protocols"][proto][port] = nm[self.target][
                        proto
                    ][port]
                    print(
                        f"Target: {self.target}, Protocol: {proto}, Port: {port}, Info: {nm[self.target][proto][port]}"
                    )
        else:
            print(f"Target {self.target} not found in scan results.")
        return results

    def custom_port_range_scan(self):
        try:
            start_port = int(input("Enter start port: ").strip())
            end_port = int(input("Enter end port: ").strip())
        except ValueError:
            self.log("Invalid port numbers entered. Please try again.")
            return self.custom_port_range_scan()
        self.log(
            f"Scanning ports from {start_port} to {end_port} on target: {self.target}"
        )
        open_ports = {}
        for port in range(start_port, end_port + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    try:
                        s.send(b"\r\n")
                        banner = s.recv(1024)
                        banner = banner.decode(errors="ignore")
                    except Exception:
                        banner = ""
                    open_ports[port] = banner
                    self.log(f"Port {port} open, banner: {banner}")
                s.close()
            except Exception as e:
                self.log(f"Error scanning port {port}: {e}")
        self.scan_results["custom_ports"] = open_ports
        return open_ports

    def nmap_scan(self):
        self.log("Performing nmap services scan on target: " + self.target)
        nm = nmap.PortScanner()
        scan_arguments = "-A"
        try:
            nm.scan(self.target, arguments=scan_arguments)
        except Exception as e:
            self.log(f"Error during nmap scan: {e}")
            self.scan_results["nmap_scan"] = {"error": str(e)}
            return self.scan_results["nmap_scan"]

        if self.target not in nm.all_hosts():
            self.log("Target not found in nmap scan results")
            self.scan_results["nmap_scan"] = {
                "error": "Target not found in nmap scan results"
            }
            return self.scan_results["nmap_scan"]

        target_info = nm[self.target]
        nmap_results = {"detailed_info": target_info, "raw": target_info}
        self.scan_results["nmap_scan"] = nmap_results
        self.log("Nmap scan results: " + str(nmap_results))
        return nmap_results

    def traceroute(self):
        self.log(
            f"Initiating traceroute on target: {self.target}. Please wait while the route is being mapped."
        )
        system_name = platform.system().lower()
        if "windows" in system_name:
            cmd = ["tracert", self.target]
        else:
            cmd = ["traceroute", self.target]
        self.log(f"Using command: {' '.join(cmd)}")
        try:
            output = subprocess.check_output(cmd, universal_newlines=True)
            self.log(
                "Traceroute completed successfully. Here is the detailed output:\n"
                + output
            )
            self.scan_results["traceroute"] = output
            return output
        except Exception as e:
            self.log(f"Error during traceroute execution: {e}")
            self.scan_results["traceroute"] = {"error": str(e)}
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
2. Nmap info scan (comprehensive target information)
3. Traceroute to target
4. Custom port range scan
5. Log results to file
6. Exit
"""
        while True:
            print(menu)
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                self.scan_ports()
            elif choice == "2":
                self.nmap_scan()
            elif choice == "3":
                self.traceroute()
            elif choice == "4":
                self.custom_port_range_scan()
            elif choice == "5":
                self.log_results_to_file()
            elif choice == "6":
                self.log("Exiting...")
                break
            else:
                self.log("Invalid choice. Please try again.")
            sleep(1)
