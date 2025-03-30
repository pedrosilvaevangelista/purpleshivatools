#!/usr/bin/env python3
import argparse
import logging
import sys
import signal
import threading
import ipaddress
import time

# Silence scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, Ether, srp
from scapy.arch import get_if_hwaddr, get_working_if

def ping_sweep_ipv4(ip_range):
    """
    Performs a Ping Sweep on an IPv4 network and prints progress.
    
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

    hosts = list(network.hosts())
    total = len(hosts)
    for i, ip in enumerate(hosts, start=1):
        # Calculate and print progress percentage
        progress = int((i / total) * 100)
        sys.stdout.write(f"\rIPv4 Progress: {progress}% ({i}/{total})")
        sys.stdout.flush()
        
        pkt = IP(dst=str(ip)) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply is not None:
            active_hosts.append(str(ip))
    sys.stdout.write("\n")  # Newline after progress completion
    print("IPv4 Active Hosts:", active_hosts)
    return active_hosts

def get_ipv6_from_ipv4(ipv4_address):
    """
    Performs NDP to find the IPv6 link-local address of a device given its IPv4 address.
    
    Parameters:
        ipv4_address (str): The IPv4 address of the target device.
    
    Returns:
        str: The IPv6 link-local address or None if not found.
    """
    iface = get_working_if()
    src_mac = get_if_hwaddr(iface)

    # Construct the solicited-node multicast address for the IPv6 target.
    ip_int = int(ipaddress.IPv4Address(ipv4_address))
    last24 = format(ip_int & 0xffffff, '06x')
    solicited_multicast = "ff02::1:ff" + last24
    dst_mac = "33:33:ff:" + last24[0:2] + ":" + last24[2:4] + ":" + last24[4:6]
    
    # Construct the NDP NS (Neighbor Solicitation) packet
    pkt = Ether(dst=dst_mac) / IPv6(src="fe80::" + src_mac, dst=solicited_multicast) / ICMPv6ND_NS(tgt=ipv4_address) / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)

    # Send the request and receive the response
    answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
    
    for sent, received in answered:
        if received:
            # Return the link-local IPv6 address
            return received[IPv6].src  # This is the router's link-local IPv6 address
    return None

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
        print("IPv6 Hosts Active (from IPv4 scan):")
        for host in ipv6_hosts:
            print(f"  {host}")
    if not ipv4_hosts and not ipv6_hosts:
        print("No active hosts found.")
    print("-----------------------------------------\n")

def menu():
    """
    Interactive mode for inputting IPv4 network and choosing whether to perform
    NDP to find IPv6 addresses for active IPv4 hosts.
    """
    ipv4_range = input("Enter IPv4 network (ex: 192.168.1.0/24) or leave blank: ").strip()
    do_ipv6 = input("Find IPv6 addresses for active IPv4 hosts? (y/N): ").strip().lower() == 'y'
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(ipv4_range)))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    if do_ipv6:
        # For each active IPv4 host, find its IPv6 address
        for ipv4 in ipv4_hosts:
            print(f"Finding IPv6 for IPv4: {ipv4}")
            ipv6 = get_ipv6_from_ipv4(ipv4)
            if ipv6:
                ipv6_hosts.append(ipv6)
        
    print_hosts(ipv4_hosts, ipv6_hosts)

def terminal():
    """
    Command-line mode using arguments.
    Use --ipv4 for IPv4 CIDR and --ipv6 flag to perform IPv6 retrieval for active IPv4 hosts.
    """
    parser = argparse.ArgumentParser(
        description="Fast IPv4 scanning and retrieving IPv6 addresses from active IPv4 hosts",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ipv4", dest="ipv4_range", help="IPv4 network range in CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--ipv6", action="store_true", help="Find IPv6 addresses for active IPv4 hosts")
    args = parser.parse_args()
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if args.ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(args.ipv4_range)))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

    if args.ipv6:
        # For each active IPv4 host, find its IPv6 address
        for ipv4 in ipv4_hosts:
            print(f"Finding IPv6 for IPv4: {ipv4}")
            ipv6 = get_ipv6_from_ipv4(ipv4)
            if ipv6:
                ipv6_hosts.append(ipv6)
        
    print_hosts(ipv4_hosts, ipv6_hosts)

def signal_handler(sig, frame):
    """
    Gracefully handle Ctrl+C interruption.
    """
    print("\nExiting Scan...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    # Use terminal mode if arguments are provided; otherwise interactive mode.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
