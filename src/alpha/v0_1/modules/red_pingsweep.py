#!/usr/bin/env python3
import argparse
import logging
import sys
import signal
import threading
import ipaddress

# Silence scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, IPv6, sr1

try:
    from tqdm import tqdm
except ImportError:
    print("tqdm module not found. Install it using: pip install tqdm")
    sys.exit(1)

def ping_sweep_ipv4(ip_range, pos=0):
    """
    Performs a Ping Sweep on an IPv4 network with progress.
    
    Parameters:
        ip_range (str): IPv4 network in CIDR format (e.g. "192.168.1.0/24").
        pos (int): Position for the tqdm progress bar.
    
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
    for ip in tqdm(hosts, desc="IPv4 Progress", unit="host", position=pos, leave=True):
        pkt = IP(dst=str(ip)) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply is not None:
            active_hosts.append(str(ip))
    print("IPv4 Active Hosts:", active_hosts)
    return active_hosts

def ndp_scan_ipv6(ip_range, pos=0):
    """
    Performs an IPv6 scan using NDP to speed up discovery on local networks.
    
    Parameters:
        ip_range (str): IPv6 network in CIDR format (typically link-local, e.g. "fe80::/64").
        pos (int): Position for the tqdm progress bar.
    
    Returns:
        list: List of active IPv6 addresses discovered via NDP.
    """
    print(f"\nStarting IPv6 NDP Scan on: {ip_range}")
    active_hosts = []
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
    except ValueError as e:
        print(f"Invalid IPv6 network: {e}")
        return active_hosts

    hosts = list(network.hosts())
    from scapy.all import Ether, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, srp
    from scapy.arch import get_if_hwaddr, get_working_if

    iface = get_working_if()
    src_mac = get_if_hwaddr(iface)

    packets = []
    for ip in tqdm(hosts, desc="IPv6 NDP Progress", unit="host", position=pos, leave=True):
        # Construct the solicited-node multicast address for the target IPv6.
        ip_int = int(ipaddress.IPv6Address(ip))
        last24 = format(ip_int & 0xffffff, '06x')
        solicited_multicast = "ff02::1:ff" + last24
        # Derive the corresponding Ethernet multicast address.
        dst_mac = "33:33:ff:" + last24[0:2] + ":" + last24[2:4] + ":" + last24[4:6]
        pkt = Ether(dst=dst_mac) / \
              IPv6(src=str(ip), dst=solicited_multicast) / \
              ICMPv6ND_NS(tgt=str(ip)) / \
              ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        packets.append(pkt)

    answered, _ = srp(packets, iface=iface, timeout=2, verbose=False)
    for sent, received in answered:
        if received:
            active_hosts.append(received[IPv6].src)
    print("IPv6 Active Hosts (NDP):", active_hosts)
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
        print("IPv6 Hosts Active (NDP):")
        for host in ipv6_hosts:
            print(f"  {host}")
    if not ipv4_hosts and not ipv6_hosts:
        print("No active hosts found.")
    print("-----------------------------------------\n")

def menu():
    """
    Interactive mode for inputting IPv4 and/or IPv6 network ranges.
    For IPv6, only the faster NDP scan is used.
    """
    ipv4_range = input("Enter IPv4 network (ex: 192.168.1.0/24) or leave blank: ").strip()
    ipv6_range = input("Enter IPv6 network (ex: fe80::/64) or leave blank: ").strip()

    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if ipv4_range:
        pos = 0
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(ipv4_range, pos)))
        threads.append(t)
        t.start()
        
    if ipv6_range:
        pos = 1 if ipv4_range else 0
        t = threading.Thread(target=lambda: ipv6_hosts.extend(ndp_scan_ipv6(ipv6_range, pos)))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print_hosts(ipv4_hosts, ipv6_hosts)

def terminal():
    """
    Command-line mode using arguments.
    Use --ipv4 for IPv4 CIDR and --ipv6 for IPv6 CIDR (NDP scan is used for IPv6).
    """
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool for IPv4 and fast IPv6 scanning via NDP",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--ipv4", dest="ipv4_range", help="IPv4 network range in CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("--ipv6", dest="ipv6_range", help="IPv6 network range in CIDR (ex: fe80::/64)")
    args = parser.parse_args()
    
    ipv4_hosts = []
    ipv6_hosts = []
    threads = []
    
    if args.ipv4_range:
        pos = 0
        t = threading.Thread(target=lambda: ipv4_hosts.extend(ping_sweep_ipv4(args.ipv4_range, pos)))
        threads.append(t)
        t.start()
        
    if args.ipv6_range:
        pos = 1 if args.ipv4_range else 0
        t = threading.Thread(target=lambda: ipv6_hosts.extend(ndp_scan_ipv6(args.ipv6_range, pos)))
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
    # Use command-line mode if arguments are provided; otherwise, interactive mode.
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
