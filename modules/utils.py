# modules/utils.py

import ipaddress
import os
import re
from typing import List

import nmap


def format_bytes(size):
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} EB"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def validate_ip_address(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        raise ValueError("Invalid IP address.")


def validate_port(port):
    return 0 <= port <= 65535


def validate_protocol(protocol):
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


def get_network_range():
    try:
        network_range = input("Enter the network range (CIDR notation): ")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", network_range):
            raise ValueError("Invalid network range. Must be in CIDR notation.")
        return network_range
    except ValueError as e:
        print(e)
        return get_network_range()
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


def scan_network(network_range: str) -> List[str]:
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


def get_target_ip(logger=print) -> str:
    try:
        selection = (
            input(
                "Select target selection method ('manual' for manual input or 'nmap' to scan network): "
            )
            .strip()
            .lower()
        )

        if selection == "manual":
            ip = get_ip_address()
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            available_ips = scan_network(str(network))
            if ip not in available_ips:
                print(
                    "The IP address you entered is not active in the network. Please try again."
                )
                return get_target_ip(logger)
            return ip

        elif selection == "nmap":
            network_range = get_network_range()
            logger(f"Scanning network range: {network_range}")
            available_ips = scan_network(network_range)
            if not available_ips:
                logger("No available IP addresses found. Please try again.")
                return get_target_ip(logger)
            logger("\nAvailable IP addresses:")
            for idx, ip in enumerate(available_ips, start=1):
                logger(f"{idx}. {ip}")
            choice = input("Select an IP by entering its number: ").strip()
            try:
                index = int(choice) - 1
                if index < 0 or index >= len(available_ips):
                    logger("Invalid selection. Please try again.")
                    return get_target_ip(logger)
                return available_ips[index]
            except ValueError:
                logger("Invalid input. Please enter a valid number.")
                return get_target_ip(logger)

        else:
            logger("Invalid selection. Please type 'manual' or 'nmap'.")
            return get_target_ip(logger)

    except KeyboardInterrupt:
        logger("\nExiting....")
        exit()
