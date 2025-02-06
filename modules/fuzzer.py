# modules/fuzzer.py

import logging
import random
from typing import Callable, List, Optional

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

    def prompt_for_parameters(self):

        try:
            dst_ip = utils.get_ip_address()
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
            method = input(
                "Enter the fuzzing method (mutation, generation, dictionary): "
            ).lower()
            if method.lower() not in self.strategies:
                print(
                    "Invalid fuzzing method. Please try again. (mutation, generation, dictionary)"
                )
                return self.get_fuzzing_method()

            else:
                return method.lower()
        except ValueError as e:
            print(f"Invalid fuzzing method: {e}")
            return self.get_fuzzing_method()
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()

    def run(self):
        dst_ip, dst_port, protocol, method, iterations, kwargs = (
            self.prompt_for_parameters()
        )
        self.fuzz(dst_ip, dst_port, protocol, method, iterations, **kwargs)

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

        print(f"Starting {method.capitalize()}-Based Fuzzing...")
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
