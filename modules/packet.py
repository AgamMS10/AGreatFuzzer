# modules/packet.py

from scapy.all import ICMP, IP, TCP, UDP, Raw, send


class PacketHandler:
    def create_packet(self, dst_ip, dst_port=None, protocol="TCP", payload=b""):
        if protocol == "TCP":
            packet = IP(dst=dst_ip) / TCP(dport=dst_port) / Raw(load=payload)
        elif protocol == "UDP":
            packet = IP(dst=dst_ip) / UDP(dport=dst_port) / Raw(load=payload)
        elif protocol == "ICMP":
            packet = IP(dst=dst_ip) / ICMP() / Raw(load=payload)
        else:
            raise ValueError("Unsupported protocol")
        return packet

    def send_packet(self, packet):
        send(packet, verbose=False)
