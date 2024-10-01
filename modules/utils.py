# modules/utils.py

import os


def format_bytes(size):
    # Converts bytes to a human-readable format
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} EB"


def parse_address(hex_address):
    ip_hex, port_hex = hex_address.split(":")
    ip = ".".join([str(int(ip_hex[i : i + 2], 16)) for i in range(6, -2, -2)])
    port = int(port_hex, 16)
    return ip, port


def tcp_state(state_hex):
    tcp_states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
        "0C": "NEW_SYN_RECV",
        "0D": "UNKNOWN",
    }
    return tcp_states.get(state_hex.upper(), "UNKNOWN")


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")
