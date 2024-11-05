# app.py

import sys
from time import sleep

from modules.active_ports import ActivePortsMonitor
from modules.connections import ConnectionsMonitor
from modules.fuzzer import Fuzzer
from modules.network_monitor import NetworkTrafficMonitor
from modules.process_stats import ProcessStats
from modules.utils import clear_screen


def main():
    while True:
        clear_screen()
        print("Welcome to AgreatFuzzer")
        print("Select an option:")
        print("1) Monitoring")
        print("2) Fuzzing")
        print("3) Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            monitoring_menu()
        elif choice == "2":
            fuzzing_menu()
        elif choice == "3":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")


def monitoring_menu():
    while True:
        clear_screen()
        print("Monitoring Menu:")
        print("1) Monitor Network Traffic")
        print("2) Monitor Active Connections")
        print("3) Monitor Active Ports")
        print("4) Display Process Information")
        print("5) Back to Main Menu")
        choice = input("Enter your choice: ")
        if choice == "1":
            monitor_network_traffic()
        elif choice == "2":
            monitor_active_connections()
        elif choice == "3":
            monitor_active_ports()
        elif choice == "4":
            display_process_information()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")


def fuzzing_menu():
    while True:
        clear_screen()
        print("Fuzzing Menu:")
        print("1) Mutation-based Fuzzing")
        print("2) Generation-based Fuzzing")
        print("3) Dictionary-based Fuzzing")
        print("4) Hybrid Fuzzing")
        print("5) Back to Main Menu")
        choice = input("Enter your choice: ")
        if choice == "1":
            mutation_fuzzing()
        elif choice == "2":
            generation_fuzzing()
        elif choice == "3":
            dictionary_fuzzing()
        elif choice == "4":
            hybrid_fuzzing()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")


# Monitoring functions
def monitor_network_traffic():
    try:
        pid = int(input("Enter the PID to monitor network traffic: "))
        interval = int(input("Enter the update interval in seconds: "))
        network_monitor = NetworkTrafficMonitor(pid)
        while True:
            sleep(interval)
            clear_screen()
            network_monitor.display_network_traffic(interval)
    except KeyboardInterrupt:
        print("Stopping network traffic monitoring.")
        input("Press Enter to return to the Monitoring Menu.")
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to return to the Monitoring Menu.")


def monitor_active_connections():
    pid = int(input("Enter the PID to monitor active connections: "))
    connections_monitor = ConnectionsMonitor(pid)
    try:
        while True:
            clear_screen()
            connections_monitor.display_connections()
    except KeyboardInterrupt:
        print("Stopping connections monitoring.")
        input("Press Enter to return to the Monitoring Menu.")


def monitor_active_ports():
    pid = int(input("Enter the PID to monitor active ports: "))
    active_ports_monitor = ActivePortsMonitor(pid)
    try:
        while True:
            clear_screen()
            active_ports_monitor.display_active_ports()
    except KeyboardInterrupt:
        print("Stopping active ports monitoring.")
        input("Press Enter to return to the Monitoring Menu.")


def display_process_information():
    pid = int(input("Enter the PID to display process information: "))
    process_stats = ProcessStats(pid)
    process_stats.display_process_info()
    input("Press Enter to return to the Monitoring Menu.")


# Fuzzing functions
def mutation_fuzzing():
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    protocol = input("Enter the protocol (TCP/UDP/ICMP): ").upper()
    iterations = int(input("Enter the number of iterations: "))
    fuzzer = Fuzzer()
    fuzzer.mutation_based_fuzzing(target_ip, target_port, protocol, iterations)
    input("Press Enter to return to the Fuzzing Menu.")


def generation_fuzzing():
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    protocol = input("Enter the protocol (TCP/UDP/ICMP): ").upper()
    iterations = int(input("Enter the number of iterations: "))
    fuzzer = Fuzzer()
    fuzzer.generation_based_fuzzing(target_ip, target_port, protocol, iterations)
    input("Press Enter to return to the Fuzzing Menu.")


def dictionary_fuzzing():
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))
    protocol = input("Enter the protocol (TCP/UDP/ICMP): ").upper()
    wordlist_file = input("Enter the path to the wordlist file: ")
    iterations = int(input("Enter the number of iterations: "))
    fuzzer = Fuzzer()
    fuzzer.dictionary_based_fuzzing(
        target_ip, target_port, protocol, wordlist_file, iterations
    )
    input("Press Enter to return to the Fuzzing Menu.")


def hybrid_fuzzing():
    print("Hybrid fuzzing is not yet implemented.")
    input("Press Enter to return to the Fuzzing Menu.")


if __name__ == "__main__":
    main()
