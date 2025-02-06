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
            # monitoring_menu()
            monitor_menu()
        elif choice == "2":
            fuzzing_menu()
        elif choice == "3":
            print("Exiting.")
            sys.exit(0)
        else:
            print("Invalid choice. Please try again.")


def fuzzing_menu():
    clear_screen()
    print("Fuzzing Menu:")
    fuzzer = Fuzzer()
    fuzzer.run()


def monitor_menu():
    clear_screen()
    print("Monitoring Menu:")
    monitor = NetworkTrafficMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
