# modules/payload_generators.py


import random
from typing import List, Optional


class PayloadGenerator:

    def generate_payload(self) -> bytes:
        raise NotImplementedError("Must implement generate_payload method.")


class MutationPayloadGenerator(PayloadGenerator):
    def __init__(self, base_payload: Optional[bytes] = None, length: int = 100):
        self.base_payload = base_payload or self.random_payload(length)
        self.length = length

    def generate_payload(self) -> bytes:
        # Simple mutation: flip a random bit in the base payload
        payload = bytearray(self.base_payload)
        if not payload:
            payload = bytearray(self.random_payload(self.length))
        byte_index = random.randint(0, len(payload) - 1)
        bit_index = random.randint(0, 7)
        payload[byte_index] ^= 1 << bit_index
        return bytes(payload)

    @staticmethod
    def random_payload(length: int) -> bytes:
        return bytes([random.randint(0, 255) for _ in range(length)])


class GenerationPayloadGenerator(PayloadGenerator):
    def __init__(self, length: int = 100):
        self.length = length

    def generate_payload(self) -> bytes:
        # Generate a completely random payload
        return bytes([random.randint(0, 255) for _ in range(self.length)])


class DictionaryPayloadGenerator(PayloadGenerator):
    def __init__(self, wordlist_file: str, default_length: int = 100):
        self.wordlist = self.load_wordlist(wordlist_file)
        self.default_length = default_length

    def generate_payload(self) -> bytes:
        if not self.wordlist:
            return GenerationPayloadGenerator(self.default_length).generate_payload()
        word = random.choice(self.wordlist)
        return word.encode()

    @staticmethod
    def load_wordlist(file_path: str) -> List[str]:
        try:
            with open(file_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except Exception as e:
            print(f"Error loading wordlist from '{file_path}': {e}")
            return []
