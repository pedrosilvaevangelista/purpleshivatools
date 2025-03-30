#!/usr/bin/env python3
import argparse
import logging
import socket
from scapy.all import IP, ICMP, sr1
import sys
import signal

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Remove warnings from Scapy


def ping_sweep(ip_range):
    """
    Perform a Ping Sweep on the specified IP range.

    Parameters:
        ip_range (str): IP range in "192.168.1.0/24" format.

    Returns:
        list: List of active IPs.
    """
    print(f"Starting Ping Sweep on range: {ip_range}")
    active_hosts = []
    
    total_ips = 254  # For a /24 range, 1 to 254
    # Loop through all the IPs in the /24 range
    for count, i in enumerate(range(1, 255), start=1):
        ip = f"192.168.1.{i}"
        pkt = IP(dst=ip)/ICMP()
        # Send ICMP packet and wait for a response
        response = sr1(pkt, timeout=1, verbose=False)
        
        if response:  # If there is a response, the host is active
            active_hosts.append(ip)
        
        # Calculate and display the completion percentage
        progress = (count / total_ips) * 100
        sys.stdout.write(f"\rProgress (IPv4): {progress:.2f}%")
        sys.stdout.flush()
    
    print()  # Skip a line after finishing
    return active_hosts


def resolve_ipv6(ipv4):
    """
    Resolve the IPv6 address for a given IPv4 address.

    Parameters:
        ipv4 (str): IPv4 address to resolve.

    Returns:
        str: IPv6 address associated with the IPv4 address.
    """
    try:
        # Get the hostname of the IPv4 address
        host = socket.gethostbyaddr(ipv4)[0]
        # Now resolve the IPv6 address using the hostname
        ipv6 = socket.getaddrinfo(host, None, socket.AF_INET6)
        # Return the first IPv6 address
        return ipv6[0][4][0]
    except (socket.herror, socket.gaierror):
        return None


def get_ipv6_addresses(ipv4_hosts):
    """
    Get the IPv6 addresses for the active IPv4 hosts.

    Parameters:
        ipv4_hosts (list): List of active IPv4 addresses.

    Returns:
        dict: Mapping of IPv4 to IPv6 addresses.
    """
    ipv6_addresses = {}
    total_ips = len(ipv4_hosts)
    
    for count, ipv4 in enumerate(ipv4_hosts, start=1):
        ipv6 = resolve_ipv6(ipv4)
        if ipv6:
            ipv6_addresses[ipv4] = ipv6
        
        # Calculate and display the progress for IPv6 resolution
        progress = (count / total_ips) * 100
        sys.stdout.write(f"\rProgress (IPv6): {progress:.2f}%")
        sys.stdout.flush()
    
    print()  # Skip a line after finishing
    return ipv6_addresses


def print_hosts(ipv4_hosts, ipv6_addresses):
    """
    Display the active hosts found with their IPv4 and IPv6 addresses.
    """
    print("\nActive Hosts Found:")
    print("-----------------------------------------")
    for host in ipv4_hosts:
        ipv6 = ipv6_addresses.get(host, "No IPv6 found")
        print(f"IPv4: {host} | IPv6: {ipv6}")


def menu():
    """
    Interactive mode to input the IP range via user input.
    """
    ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
    ipv4_hosts = ping_sweep(ip_range)
    ipv6_addresses = get_ipv6_addresses(ipv4_hosts)
    print_hosts(ipv4_hosts, ipv6_addresses)


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
    args = parser.parse_args()
    ipv4_hosts = ping_sweep(args.ip_range)
    ipv6_addresses = get_ipv6_addresses(ipv4_hosts)
    print_hosts(ipv4_hosts, ipv6_addresses)


def signal_handler(sig, frame):
    """
    Handle the interrupt signal (Ctrl+C) to exit the program gracefully.
    """
    print("\nExiting Ping Sweep...")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    # If there are command-line arguments, use terminal mode; otherwise, use interactive mode
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()


if __name__ == "__main__":
    main()
