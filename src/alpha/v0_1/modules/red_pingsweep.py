#!/usr/bin/env python3
import argparse
import logging
import sys
import signal
import threading
import ipaddress

# Silence scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, IPv6, ICMPv6EchoRequest, sr, sr1

def ping_sweep_ipv4(ip_range):
    """
    Performs a Ping Sweep on an IPv4 network.
    
    Parameters:
        ip_range (str): IPv4 network in CIDR format (e.g. "192.168.1.0/24").
    
    Returns:
        list: List of active IPv4 addresses.
    """
    print(f"\nStarting IPv4 Ping Sweep on: {ip_range}")
    active_hosts = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        print(f"Invalid IPv4 network: {e}")
        return active_hosts

    # Create packets for each host in the network (skip network and broadcast addresses)
    hosts = list(network.hosts())
    packets = [IP(dst=str(ip))/ICMP() for ip in hosts]
    
    # Send packets in parallel and wait for responses
    answered, _ = sr(packets, timeout=1, verbose=False)
    
    # Extract active hosts
    for sent, received in answered:
        if received and IP in received:
            active_hosts.append(received[IP].src)
    
    print("IPv4 Active Hosts:", active_hosts)
    return active_hosts

def ping_sweep_ipv6(ip_range):
    """
    Performs a Ping Sweep on an IPv6 network.
    
    Parameters:
        ip_range (str): IPv6 network in CIDR format (e.g. "2001:db8::/120").
    
    Returns:
        list: List of active IPv6 addresses.
    """
    print(f"\nStarting IPv6 Ping Sweep on: {ip_range}")
    active_hosts = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        print(f"Invalid IPv6 network: {e}")
        return active_hosts

    # Create packets for each host in the network (caution: IPv6 networks can be huge!)
    hosts = list(network.hosts())
    packets = [IPv6(dst=str(ip))/ICMPv6EchoRequest() for ip in hosts]
    
    # Send packets and wait for responses
    answered, _ = sr(packets, timeout=1, verbose=False)
    
    # Extract active hosts
    for sent, received in answered:
        if received and IPv6 in received:
            active_hosts.append(received[IPv6].src)
    
    print("IPv6 Active Hosts:", active_hosts)
    return active_hosts

def print_hosts(ipv4_hosts, ipv6_hosts):
    """
    Displays active hosts found for IPv4 and IPv6.
    """
    print("\n-----------------------------------------")
    if ipv4_hosts:
        print("IPv4 Hosts Active:")
        for host in ipv4_hosts:
            print(f"  {host}")
    if ipv6_hosts:
        print("IPv6 Hosts Active:")
        for host in ipv6_hosts:
            print(f"  {host}")
    if not ipv4_hosts and not ipv6_hosts:
        print("No active hosts found.")
    print("-----------------------------------------\n")

def menu():
    """
    Interactive mode to input the IPv4 and/or IPv6 network ranges.
    """
    ipv4_range = input("Enter IPv4 network (ex: 192.168.1.0/24) or leave blank: ").strip()
    ipv6_range = input("Enter IPv6 network (ex: 2001:db8::/120) or leave blank: ").strip()
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(ipv4_range)))
        threads.append(t)
        t.start()
        
    if ipv6_range:
        t = threading.Thread(target=lambda: ipv6_hosts.extend(ping_sweep_ipv6(ipv6_range)))
        threads.append(t)
        t.start()
    
    # Wait for all threads to finish
    for t in threads:
        t.join()
    
    print_hosts(ipv4_hosts, ipv6_hosts)

def terminal():
    """
    Command-line mode using arguments.
    """
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool for IPv4 and IPv6 networks",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ipv4", dest="ipv4_range", help="IPv4 network range in CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--ipv6", dest="ipv6_range", help="IPv6 network range in CIDR (ex: 2001:db8::/120)")
    args = parser.parse_args()
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if args.ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(args.ipv4_range)))
        threads.append(t)
        t.start()
        
    if args.ipv6_range:
        t = threading.Thread(target=lambda: ipv6_hosts.extend(ping_sweep_ipv6(args.ipv6_range)))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
    
    print_hosts(ipv4_hosts, ipv6_hosts)

def signal_handler(sig, frame):
    """
    Gracefully handle Ctrl+C interruption.
    """
    print("\nExiting Ping Sweep...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    # If command-line arguments are provided, use terminal mode; otherwise interactive.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
