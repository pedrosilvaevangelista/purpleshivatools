#!/usr/bin/env python3
import argparse
import logging
import socket
import sys
import signal
from scapy.all import IP, ICMP, sr, sr1, send

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Remove Scapy warnings

def get_ipv6_address(host):
    """
    Obtains the IPv6 address of a host, if available.
    
    Parameters:
        host (str): IPv4 address of the host.
    
    Returns:
        str: IPv6 address of the host or a message indicating no IPv6 available.
    """
    try:
        ipv6 = socket.getaddrinfo(host, None, socket.AF_INET6)
        return ipv6[0][4][0]  # Returns the first IPv6 address found
    except socket.gaierror:
        return None  # If no IPv6 address is found


def ping_sweep(ip_range, get_ipv6=False):
    """
    Performs a Ping Sweep on the specified IP range and optionally obtains IPv6 addresses.

    Parameters:
        ip_range (str): IP range in CIDR format (e.g., "192.168.1.0/24").
        get_ipv6 (bool): If True, it will fetch IPv6 addresses of active hosts.

    Returns:
        list: List of IPv4 addresses of active hosts found.
    """
    print(f"Starting Ping Sweep on range: {ip_range}")
    active_hosts = []
    
    total_ips = 254  # For a /24 range, from 1 to 254
    ips = [f"192.168.1.{i}" for i in range(1, 255)]

    # Create ICMP packets for all IPs
    packets = [IP(dst=ip)/ICMP() for ip in ips]

    # Send packets in parallel and wait for responses
    answered, unanswered = sr(packets, timeout=1, verbose=False)

    # Extract active hosts (those that responded)
    active_hosts = [resp[0][IP].dst for resp in answered]

    # Display progress for the IPv4 scan
    for count, ip in enumerate(ips, 1):
        progress = (count / total_ips) * 100
        sys.stdout.write(f"\rProgress: {progress:.2f}% - Checking {ip}")
        sys.stdout.flush()

    print(f"\nActive hosts found: {len(active_hosts)}")

    # If IPv6 scan is requested, proceed after IPv4 scan
    if get_ipv6:
        ipv6_addresses = {}
        for count, host in enumerate(active_hosts, 1):
            ipv6 = get_ipv6_address(host)
            if ipv6:
                ipv6_addresses[host] = ipv6
            else:
                ipv6_addresses[host] = "No IPv6"
            
            # Display progress for the IPv6 scan
            progress = (count / len(active_hosts)) * 100
            sys.stdout.write(f"\rProgress: {progress:.2f}% - Resolving IPv6 for {host}")
            sys.stdout.flush()

        print("\nIPv6 addresses found:")
        for host, ipv6 in ipv6_addresses.items():
            print(f"{host} -> {ipv6}")

    return active_hosts


def print_hosts(hosts):
    """
    Displays the active hosts found.
    """
    print("\nActive hosts found:")
    print("-----------------------------------------")
    for host in hosts:
        print(f"{host}")


def menu():
    """
    Interactive mode for entering IP range via input.
    """
    ip_range = input("Enter the IP range (e.g., 192.168.1.0/24): ")
    get_ipv6 = input("Do you want to fetch IPv6 addresses? (y/n): ").lower() == 'y'
    hosts = ping_sweep(ip_range, get_ipv6)
    print_hosts(hosts)


def terminal():
    """
    Command-line mode using arguments.
    """
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True,
                        help="IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-v6", "--get_ipv6", action="store_true", 
                        help="Fetch IPv6 addresses of active hosts")
    args = parser.parse_args()
    hosts = ping_sweep(args.ip_range, args.get_ipv6)
    print_hosts(hosts)


def signal_handler(sig, frame):
    """
    Handles the interrupt signal (Ctrl+C) to gracefully shut down the program.
    """
    print("\nShutting down the Ping Sweep...")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    # If command-line arguments are provided, use terminal mode; otherwise, use interactive mode.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()


if __name__ == "__main__":
    main()
