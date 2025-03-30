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
from scapy.all import IP, ICMP, IPv6, sr1

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

def fast_ipv6_multicast_scan(timeout=2):
    """
    Performs a fast IPv6 scan by sending a single ICMPv6 Echo Request to the
    all-nodes multicast address (ff02::1). This method is extremely fast because 
    it sends just one packet, but note that not all hosts may respond.
    
    Returns:
        list: List of active IPv6 addresses that responded.
    """
    from scapy.all import Ether, IPv6, ICMPv6EchoRequest, srp
    from scapy.arch import get_working_if

    print("\nStarting fast IPv6 multicast scan...")
    iface = get_working_if()
    # For IPv6 multicast, the typical Ethernet destination is 33:33:00:00:00:01 for ff02::1.
    pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    answered, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False)
    active_hosts = []
    for sent, received in answered:
        active_hosts.append(received[IPv6].src)
    print("Fast IPv6 multicast scan active hosts:", active_hosts)
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
        print("IPv6 Hosts Active (Fast Multicast):")
        for host in ipv6_hosts:
            print(f"  {host}")
    if not ipv4_hosts and not ipv6_hosts:
        print("No active hosts found.")
    print("-----------------------------------------\n")

def menu():
    """
    Interactive mode for inputting IPv4 network and choosing whether to perform
    a fast IPv6 multicast scan.
    """
    ipv4_range = input("Enter IPv4 network (ex: 192.168.1.0/24) or leave blank: ").strip()
    do_ipv6 = input("Perform fast IPv6 multicast scan? (y/N): ").strip().lower() == 'y'
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(ipv4_range)))
        threads.append(t)
        t.start()
    
    if do_ipv6:
        t = threading.Thread(target=lambda: ipv6_hosts.extend(fast_ipv6_multicast_scan()))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print_hosts(ipv4_hosts, ipv6_hosts)

def terminal():
    """
    Command-line mode using arguments.
    Use --ipv4 for IPv4 CIDR and --ipv6 flag to perform the fast IPv6 multicast scan.
    """
    parser = argparse.ArgumentParser(
        description="Fast IPv4 and IPv6 scanning (IPv6 via multicast ping) with manual progress",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ipv4", dest="ipv4_range", help="IPv4 network range in CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--ipv6", action="store_true", help="Perform fast IPv6 multicast scan")
    args = parser.parse_args()
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if args.ipv4_range:
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(args.ipv4_range)))
        threads.append(t)
        t.start()
    
    if args.ipv6:
        t = threading.Thread(target=lambda: ipv6_hosts.extend(fast_ipv6_multicast_scan()))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
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
