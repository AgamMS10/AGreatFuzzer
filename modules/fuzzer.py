# modules/fuzzer.py

import json
from time import sleep

from scapy.all import sr1

from modules import packet, payload_generator, utils


class Fuzzer:
    def __init__(self, target, wordlist_file=None, verbose=True):
        self.target = target
        self.verbose = verbose
        self.fuzz_results = {}
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

    def itterations(self):
        try:
            iterations = int(input("Enter the number of iterations: "))
            return iterations
        except ValueError:
            self.log("Invalid input. Please enter a valid number.")
            return self.itterations()
        except KeyboardInterrupt:
            self.log("\nExiting....")
            exit

    def fuzz_type(self):
        try:
            fuzz_type = (
                input(
                    "Select fuzzing type ('mutation', 'generation', or 'dictionary'): "
                )
                .strip()
                .lower()
            )
            if fuzz_type not in ["mutation", "generation", "dictionary"]:
                self.log("Invalid selection. Please try again.")
                return self.fuzz_type()
            return fuzz_type
        except KeyboardInterrupt:
            self.log("\nExiting....")
            exit()

    def prompt_fuzzing_options(self):
        fuzz_type = self.fuzz_type()
        iterations = self.itterations()
        options = {"fuzzing_type": fuzz_type, "iterations": iterations}

        if fuzz_type == "dictionary":
            dict_file = utils.get_file()
            options["dictionary_file"] = dict_file
            self.dictionary_gen = payload_generator.DictionaryPayloadGenerator(
                dict_file
            )
        return options

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

    def fuzz_mutation(self, protocol, port=None, iterations=5):
        self.log(
            f"Starting mutation-based fuzzing for {protocol} on port {port if port else 'N/A'}"
        )
        return self.fuzz_protocol(
            protocol,
            port=port,
            payload_generator=self.mutation_gen,
            iterations=iterations,
        )

    def fuzz_generation(self, protocol, port=None, iterations=5):
        self.log(
            f"Starting generation-based fuzzing for {protocol} on port {port if port else 'N/A'}"
        )
        return self.fuzz_protocol(
            protocol,
            port=port,
            payload_generator=self.generation_gen,
            iterations=iterations,
        )

    def fuzz_dictionary(self, protocol, port=None, iterations=5):
        self.log(
            f"Starting dictionary-based fuzzing for {protocol} on port {port if port else 'N/A'}"
        )
        return self.fuzz_protocol(
            protocol,
            port=port,
            payload_generator=self.dictionary_gen,
            iterations=iterations,
        )

    def fuzz(self, fuzz_options):
        fuzz_data = {}
        protocols = ["TCP", "UDP", "ICMP"]
        fuzzing_type = fuzz_options["fuzzing_type"]

        for protocol in protocols:
            if protocol in ["TCP", "UDP"]:
                ports = [80, 443]
                proto_responses = {}
                for port in ports:
                    if fuzzing_type == "mutation":
                        responses = self.fuzz_mutation(
                            protocol, port=port, iterations=fuzz_options["iterations"]
                        )
                    elif fuzzing_type == "generation":
                        responses = self.fuzz_generation(
                            protocol, port=port, iterations=fuzz_options["iterations"]
                        )
                    elif fuzzing_type == "dictionary":
                        responses = self.fuzz_dictionary(
                            protocol, port=port, iterations=fuzz_options["iterations"]
                        )
                    else:
                        self.log(
                            "Invalid fuzzing type selected. Aborting fuzzing process."
                        )
                        return {}
                    proto_responses[port] = responses
                fuzz_data[protocol] = proto_responses
            elif protocol == "ICMP":
                if fuzzing_type == "mutation":
                    responses = self.fuzz_mutation(
                        protocol, iterations=fuzz_options["iterations"]
                    )
                elif fuzzing_type == "generation":
                    responses = self.fuzz_generation(
                        protocol, iterations=fuzz_options["iterations"]
                    )
                elif fuzzing_type == "dictionary":
                    responses = self.fuzz_dictionary(
                        protocol, iterations=fuzz_options["iterations"]
                    )
                else:
                    self.log("Invalid fuzzing type selected. Aborting fuzzing process.")
                    return {}
                fuzz_data[protocol] = responses

        self.fuzz_results["fuzzing"] = fuzz_data
        return fuzz_data

    def log_results_to_file(self, filename="fuzz_results.log"):
        try:
            with open(filename, "w") as f:
                json.dump(self.fuzz_results, f, indent=4)
            self.log(f"Fuzzing results successfully logged to {filename}")
        except Exception as e:
            self.log(f"Failed to log fuzzing results to file: {e}")

    def run(self):
        try:
            self.log("Starting fuzzing process on target: " + self.target)
            fuzz_options = self.prompt_fuzzing_options()
            self.fuzz(fuzz_options)
            self.log_results_to_file()
            self.log(
                "Fuzzing complete. Results collected and logged to 'fuzz_results.log'"
            )
            self.log("\nPress Ctrl+C to return to the main menu.")
            while True:
                sleep(1)
        except KeyboardInterrupt:
            self.log("\nReturning to main menu...")
