# modules/utils.py

import ipaddress
import os
import re


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


def validate_ip_address(ip_address):
    """
    Validates an IP address.

    Parameters:
    ip_address (str): The IP address to validate.

    Returns:
    bool: True if the IP address is valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        raise ValueError("Invalid IP address.")


def validate_port(port):
    """
    Validates a port number.

    Parameters:
    port (int): The port number to validate.

    Returns:
    bool: True if the port number is valid, False otherwise.
    """
    return 0 <= port <= 65535


def validate_protocol(protocol):
    """
    Validates a protocol.

    Parameters:
    protocol (str): The protocol to validate.

    Returns:
    bool: True if the protocol is valid, False otherwise.
    """
    return protocol.upper() in ["TCP", "UDP", "ICMP"]  # Can add more protocols here


def get_file():
    while True:
        try:
            filename = input("Enter the path to the file: ")
            if not isinstance(filename, str):
                raise ValueError("Filename must be a string.")
            if filename.strip() == "":
                raise ValueError("Filename cannot be empty or whitespace.")
            invalid_chars = '<>:"/\\|?*'
            if any(char in filename for char in invalid_chars):
                raise ValueError(
                    f"Filename contains invalid characters: {invalid_chars}"
                )

            cwd = os.getcwd()
            file = os.path.join(cwd, filename)
            if os.path.isfile(file):
                return file
            else:
                raise FileNotFoundError(
                    f"File '{file}' not found in the current directory."
                )

        except ValueError as e:
            print(e)
        except FileNotFoundError as e:
            print(e)
        except KeyboardInterrupt:
            print("\nExiting....")
            exit()


def get_ip_address():
    try:
        ip_address = input("Enter the IP address: ")
        validate_ip_address(ip_address)
        return ip_address
    except ValueError as e:
        print(e)
        return get_ip_address()
    except KeyboardInterrupt:
        print("\nExiting....")
        exit()


def get_port():
    try:
        port = int(input("Enter the target port: "))
        validate_port(port)
        return port
    except ValueError as e:
        print(f"Invalid port must be an integer between 0 and 65535")
        return get_port()
    except KeyboardInterrupt:
        print("\nExiting....")
        exit()


def get_protocol():
    try:
        protocol = input("Enter the protocol (TCP/UDP/ICMP): ").upper()

        if validate_protocol(protocol) == False:
            print(f"Sorry, {protocol} not supported/invalid. Please try again.")
            return get_protocol()
        return protocol
    except ValueError as e:
        print(f"Invalid protocol: {e}")
        return get_protocol()
    except KeyboardInterrupt:
        print("\nExiting....")
        exit()


def get_number(prompt):
    try:
        number = int(input(f"Enter the number of {prompt}: "))
        return number
    except ValueError as e:
        print(f"Invalid number of iterations: {e}")
        return get_number(prompt)
    except KeyboardInterrupt:
        print("\nExiting....")
        exit()
