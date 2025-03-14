# modules/fuzzer.py

import json
import platform
import socket
from time import sleep

import nmap
from scapy.all import conf, sr1

from modules import packet, payload_generator, utils


class Fuzzer:
    def __init__(self, target=None, wordlist_file=None, verbose=True):
        self.target = target if target else self.get_target_ip()
        self.verbose = verbose
        self.results = {}
        self.wordlist_file = wordlist_file
        self.packet_handler = packet.PacketHandler()
        self.mutation_gen = payload_generator.MutationPayloadGenerator()
        self.generation_gen = payload_generator.GenerationPayloadGenerator()
        self.dictionary_gen = (
            payload_generator.DictionaryPayloadGenerator(wordlist_file)
            if wordlist_file
            else None
        )

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
                print(f"Scanning network range: {network_range}")
                available_ips = utils.scan_network(network_range)
                if not available_ips:
                    print("No available IP addresses found. Please try again.")
                    return self.get_target_ip()
                print("\nAvailable IP addresses:")
                for idx, ip in enumerate(available_ips, start=1):
                    print(f"{idx}. {ip}")
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

    def scan_ports(self):
        self.log("Scanning common ports on target: " + self.target)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995]
        open_ports = {}
        for port in common_ports:
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
        self.results["open_ports"] = open_ports
        return open_ports

    def nmap_scan(self):
        self.log(
            "Performing nmap scan for OS and service detection on target: "
            + self.target
        )
        nm = nmap.PortScanner()
        scan_arguments = "-O -sV"
        try:
            nm.scan(self.target, arguments=scan_arguments)
        except Exception as e:
            self.log(f"Error during nmap scan: {e}")
            self.results["nmap_scan"] = {"error": str(e)}
            return self.results["nmap_scan"]

        if self.target not in nm.all_hosts():
            self.log("Target not found in nmap scan results")
            self.results["nmap_scan"] = {
                "error": "Target not found in nmap scan results"
            }
            return self.results["nmap_scan"]

        target_info = nm[self.target]
        os_matches = target_info.get("osmatch", [])
        services = target_info.get("tcp", {})
        nmap_results = {
            "os_matches": os_matches,
            "services": services,
            "raw": target_info,
        }
        self.results["nmap_scan"] = nmap_results
        self.log("Nmap scan results: " + str(nmap_results))
        return nmap_results

    def prompt_fuzzing_options(self):

        fuzz_type = (
            input(
                "Enter fuzzing type ('mutation_generation' for Mutation/Generation fuzzing or 'dictionary' for Dictionary fuzzing): "
            )
            .strip()
            .lower()
        )

        try:
            iterations = int(
                input("Enter the number of iterations for each fuzzing round: ").strip()
            )
        except ValueError:
            self.log("Invalid iteration count. Using default of 3 iterations.")
            iterations = 3

        options = {"fuzzing_type": fuzz_type, "iterations": iterations}

        if fuzz_type == "dictionary":
            dict_file = utils.get_file()
            options["dictionary_file"] = dict_file
            self.dictionary_gen = payload_generator.DictionaryPayloadGenerator(
                dict_file
            )
        return options

    def log_results_to_file(self, filename="fuzz_results.log"):

        try:
            with open(filename, "w") as f:
                json.dump(self.results, f, indent=4)
            self.log(f"Results successfully logged to {filename}")
        except Exception as e:
            self.log(f"Failed to log results to file: {e}")

    def fuzz_protocol(self, protocol, port=None, payload_generator=None, iterations=5):
        self.log(
            f"Fuzzing {protocol} on port {port if port else 'N/A'} with {iterations} iterations"
        )
        responses = []
        for i in range(iterations):
            try:
                payload = (
                    payload_generator.generate_payload()
                    if payload_generator
                    else self.generation_gen.generate_payload()
                )
                pkt = self.packet_handler.create_packet(
                    dst_ip=self.target,
                    dst_port=port,
                    protocol=protocol,
                    payload=payload,
                )
                response = sr1(pkt, timeout=2, verbose=0)
                responses.append(response)
                if response:
                    self.log(f"Iteration {i}: Received response: {response.summary()}")
                else:
                    self.log(f"Iteration {i}: No response received")
            except Exception as e:
                self.log(f"Error on iteration {i} for {protocol}: {e}")
        return responses

    def fuzz(self, fuzz_options):
        fuzz_data = {}
        protocols = ["TCP", "UDP", "ICMP"]
        for protocol in protocols:
            if protocol in ["TCP", "UDP"]:
                ports = [80, 443]
                proto_responses = {}
                for port in ports:
                    if fuzz_options["fuzzing_type"] == "mutation_generation":
                        responses = {
                            "mutation": self.fuzz_protocol(
                                protocol,
                                port=port,
                                payload_generator=self.mutation_gen,
                                iterations=fuzz_options["iterations"],
                            ),
                            "generation": self.fuzz_protocol(
                                protocol,
                                port=port,
                                payload_generator=self.generation_gen,
                                iterations=fuzz_options["iterations"],
                            ),
                        }
                    elif fuzz_options["fuzzing_type"] == "dictionary":
                        responses = {
                            "dictionary": self.fuzz_protocol(
                                protocol,
                                port=port,
                                payload_generator=self.dictionary_gen,
                                iterations=fuzz_options["iterations"],
                            )
                        }
                    else:
                        self.log(
                            "Invalid fuzzing type selected. Aborting fuzzing process."
                        )
                        return {}
                    proto_responses[port] = responses
                fuzz_data[protocol] = proto_responses
            elif protocol == "ICMP":
                if fuzz_options["fuzzing_type"] == "mutation_generation":
                    responses = {
                        "mutation": self.fuzz_protocol(
                            protocol,
                            payload_generator=self.mutation_gen,
                            iterations=fuzz_options["iterations"],
                        ),
                        "generation": self.fuzz_protocol(
                            protocol,
                            payload_generator=self.generation_gen,
                            iterations=fuzz_options["iterations"],
                        ),
                    }
                elif fuzz_options["fuzzing_type"] == "dictionary":
                    responses = {
                        "dictionary": self.fuzz_protocol(
                            protocol,
                            payload_generator=self.dictionary_gen,
                            iterations=fuzz_options["iterations"],
                        )
                    }
                fuzz_data[protocol] = responses

        self.results["fuzzing"] = fuzz_data
        return fuzz_data

    def run(self):
        """
        Runs the complete fuzzing process:
        1. Performs an nmap scan to gather target information.
        2. Prompts the user for fuzzing options.
        3. Scans ports and executes fuzzing rounds using the selected payload generator(s).
        4. Logs the collected target information and fuzzing results to a file.
        """
        try:
            self.log("Starting fuzzing process on target: " + self.target)
            # Run nmap info scan first
            self.nmap_scan()
            # Log collected information to file
            self.log_results_to_file()
            # Prompt user for fuzzing options
            fuzz_options = self.prompt_fuzzing_options()
            # Scan common ports
            self.scan_ports()
            # Perform fuzzing based on user-selected options
            self.fuzz(fuzz_options)

            self.log(
                "Fuzzing complete. Results collected and logged to 'fuzz_results.log'"
            )
            self.log("\nPress Ctrl+C to return to the main menu.")
            while True:
                sleep(1)
        except KeyboardInterrupt:
            self.log("\nReturning to main menu...")
