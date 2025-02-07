# modules/fuzzer.py

import logging
import random
from time import sleep
from typing import Callable, List, Optional

import nmap  # New: Import nmap for network scanning

from modules.packet import PacketHandler
from modules.payload_generator import (
    DictionaryPayloadGenerator,
    GenerationPayloadGenerator,
    MutationPayloadGenerator,
    PayloadGenerator,
)

from . import utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class Fuzzer:
    def __init__(self):
        self.packet_handler = PacketHandler()
        self.payload_generator: Optional[PayloadGenerator] = None
        self.strategies = {
            "mutation": MutationPayloadGenerator,
            "generation": GenerationPayloadGenerator,
            "dictionary": DictionaryPayloadGenerator,
        }

    def get_target_ip(self) -> str:
        """
        Prompt the user for the target selection method.
        Either a manual IP address input or an NMAP network scan.
        """
        try:
            selection = (
                input(
                    "Select target selection method ('manual' for manual input or 'nmap' to scan network): "
                )
                .strip()
                .lower()
            )
            if selection == "manual":
                # Use existing helper to get an IP address
                return utils.get_ip_address()
            elif selection == "nmap":
                # Ask the user for the network range to scan
                network_range = input(
                    "Enter network range to scan (e.g., 192.168.1.0/24): "
                ).strip()
                available_ips = self.scan_network(network_range)
                if not available_ips:
                    print("No available IP addresses found. Please try again.")
                    return self.get_target_ip()
                # Display the discovered IP addresses
                print("\nAvailable IP addresses:")
                for idx, ip in enumerate(available_ips, start=1):
                    print(f"{idx}. {ip}")
                # Let the user choose one by number
                choice = input("Select an IP by entering its number: ").strip()
                try:
                    index = int(choice) - 1
                    if index < 0 or index >= len(available_ips):
                        print("Invalid selection. Please try again.")
                        return self.get_target_ip()
                    return available_ips[index]
                except ValueError:
                    print("Invalid input. Please enter a valid number.")
                    return self.get_target_ip()
            else:
                print("Invalid selection. Please type 'manual' or 'nmap'.")
                return self.get_target_ip()
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()

    def scan_network(self, network_range: str) -> List[str]:
        """
        Uses nmap to perform a ping scan (-sn) on the provided network range and
        returns a list of IP addresses that are up.
        """
        scanner = nmap.PortScanner()
        try:
            scanner.scan(hosts=network_range, arguments="-sn")
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []
        available_ips = []
        for host in scanner.all_hosts():
            # Check if the host is up
            if scanner[host].state() == "up":
                available_ips.append(host)
        return available_ips

    def prompt_for_parameters(self):
        """
        Prompt for all parameters necessary for fuzzing.
        The target IP is now determined by asking the user first whether to
        manually input it or select one from an NMAP scan.
        """
        try:
            # New: Prompt for target IP selection method (manual or nmap)
            dst_ip = self.get_target_ip()
            dst_port = utils.get_port()
            protocol = utils.get_protocol()
            method = self.get_fuzzing_method()
            iterations = utils.get_number("iterations")
            # Additional parameters for specific strategies
            kwargs = {}
            if method == "dictionary":
                kwargs["wordlist_file"] = utils.get_file()

        except ValueError as e:
            print("\nInvalid input. Please try again.")
            return self.prompt_for_parameters()
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()

        return dst_ip, dst_port, protocol, method, iterations, kwargs

    def get_fuzzing_method(self):
        try:
            method = (
                input("Enter the fuzzing method (mutation, generation, dictionary): ")
                .lower()
                .strip()
            )
            if method not in self.strategies:
                print(
                    "Invalid fuzzing method. Please try again. (mutation, generation, dictionary)"
                )
                return self.get_fuzzing_method()
            else:
                return method
        except ValueError as e:
            print(f"Invalid fuzzing method: {e}")
            return self.get_fuzzing_method()
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()

    def run(self):
        while True:
            dst_ip, dst_port, protocol, method, iterations, kwargs = (
                self.prompt_for_parameters()
            )
            self.fuzz(dst_ip, dst_port, protocol, method, iterations, **kwargs)

            while True:
                choice = (
                    input("\nDo you want to run another fuzzing session? (Y/N): ")
                    .strip()
                    .lower()
                )
                if choice in ("y", "yes"):
                    break
                elif choice in ("n", "no"):
                    print("Returning to the main application...\n")
                    return
                else:
                    print("Invalid input. Please type 'Y' or 'N'.")

    def set_strategy(self, strategy_name: str, **kwargs):
        strategy_class = self.strategies.get(strategy_name.lower())
        if not strategy_class:
            print(f"Fuzzing strategy '{strategy_name}' not recognized.")
            raise ValueError(f"Unsupported fuzzing strategy: {strategy_name}")
        self.payload_generator = strategy_class(**kwargs)
        print(f"Strategy set to {strategy_name.capitalize()}PayloadGenerator")

    def fuzz(
        self,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        method: str,
        iterations: int,
        **kwargs,
    ):
        """
        General fuzzing method that delegates to the selected fuzzing strategy.

        :param dst_ip: Destination IP address
        :param dst_port: Destination port
        :param protocol: Protocol to use (e.g., 'TCP', 'UDP')
        :param method: Fuzzing method ('mutation', 'generation', 'dictionary')
        :param iterations: Number of fuzzing iterations
        :param kwargs: Additional arguments specific to the fuzzing strategy
        """
        try:
            self.set_strategy(method, **kwargs)
        except ValueError as e:
            print(f"An error occurred: {e}")
            return

        print(f"Starting {method.capitalize()}-Based Fuzzing on {dst_ip}...")
        for i in range(1, iterations + 1):
            try:
                payload = self.payload_generator.generate_payload()
                packet = self.packet_handler.create_packet(
                    dst_ip, dst_port, protocol, payload
                )
                self.packet_handler.send_packet(packet)
                print(packet)
                print(f"Iteration {i}: Packet sent successfully.")
            except Exception as e:
                print(f"Iteration {i}: Failed to send packet. Error: {e}")
        print(f"{method.capitalize()}-Based Fuzzing Completed.")
