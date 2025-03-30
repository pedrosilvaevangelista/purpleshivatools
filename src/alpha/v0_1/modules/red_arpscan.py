#!/usr/bin/env python3
import argparse
import logging
import sys
import signal
from scapy.all import IPv6, ICMPv6ND_NS, sr

# Silence Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ndp_link_local_sweep(iface):
    """
    Performs an IPv6 NDP sweep for link-local addresses (fe80::/64).
    This uses the multicast address ff02::1 to request Neighbor Advertisements from all active devices.
    """
    print(f"\n[IPv6 Link-Local] Starting NDP sweep on the link-local network (fe80::/64).")
    active_hosts = []

    # Use the link-local multicast address to query all devices on the local network
    multicast_address = "ff02::1"  # All nodes on the local link

    # Send Neighbor Solicitation (NS) messages to the multicast address
    ns_request = IPv6(dst=multicast_address) / ICMPv6ND_NS()
    
    # Send the request and wait for responses
    answered, _ = sr(ns_request, timeout=1, verbose=False, iface=iface)
    
    for sent, received in answered:
        if received and IPv6 in received:
            active_hosts.append(received[IPv6].src)

    print("[IPv6 Link-Local] Active Hosts:", active_hosts)
    return active_hosts

def print_hosts(hosts):
    """
    Displays the discovered IPv6 link-local hosts.
    """
    print("\n-----------------------------------------")
    if hosts:
        print("IPv6 Link-Local Active Hosts:")
        for host in hosts:
            print(f"  {host}")
    else:
        print("No active hosts found.")
    print("-----------------------------------------\n")

def menu():
    """
    Interactive mode for user input.
    """
    iface = input("Enter network interface for IPv6 link-local scanning (e.g., eth0, wlan0): ").strip()

    if not iface:
        print("Error: You must specify a network interface for IPv6 link-local scanning.")
        return

    hosts = ndp_link_local_sweep(iface)
    print_hosts(hosts)

def terminal():
    """
    Command-line mode using arguments.
    """
    parser = argparse.ArgumentParser(
        description="IPv6 Link-Local NDP Sweep Tool\n" +
                    "This tool uses Neighbor Solicitation to discover devices on a link-local network (fe80::/64).",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--iface", required=True, help="Network interface for IPv6 scanning (e.g., eth0, wlan0)")
    args = parser.parse_args()

    hosts = ndp_link_local_sweep(args.iface)
    print_hosts(hosts)

def signal_handler(sig, frame):
    """
    Gracefully exit on Ctrl+C.
    """
    print("\nExiting NDP Sweep...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    # Use command-line mode if arguments are provided; otherwise, interactive mode.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
