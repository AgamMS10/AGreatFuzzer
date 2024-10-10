# modules/fuzzer.py

import random

from modules.packet import PacketGenerator


class Fuzzer:
    def __init__(self):
        self.packet_gen = PacketGenerator()

    def mutation_based_fuzzing(self, dst_ip, dst_port, protocol, iterations):
        print("Starting Mutation-based Fuzzing...")
        for _ in range(iterations):
            print("Iteration: ", _)
            payload = self.random_payload()
            packet = self.packet_gen.create_packet(dst_ip, dst_port, protocol, payload)
            self.packet_gen.send_packet(packet)
        print("Mutation-based Fuzzing Completed.")

    def generation_based_fuzzing(self, dst_ip, dst_port, protocol, iterations):
        print("Starting Generation-based Fuzzing...")
        for _ in range(iterations):
            print("Iteration: ", _)
            payload = self.random_payload()
            packet = self.packet_gen.create_packet(dst_ip, dst_port, protocol, payload)
            self.packet_gen.send_packet(packet)
        print("Generation-based Fuzzing Completed.")

    def dictionary_based_fuzzing(
        self, dst_ip, dst_port, protocol, wordlist_file, iterations
    ):
        print("Starting Dictionary-based Fuzzing...")
        wordlist = self.load_wordlist(wordlist_file)
        for _ in range(iterations):
            print("Iteration: ", _)
            payload = random.choice(wordlist).encode()
            packet = self.packet_gen.create_packet(dst_ip, dst_port, protocol, payload)
            self.packet_gen.send_packet(packet)
        print("Dictionary-based Fuzzing Completed.")

    def random_payload(self, length=100):
        return bytes([random.randint(0, 255) for _ in range(length)])

    def load_wordlist(self, file_path):
        try:
            with open(file_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return []
