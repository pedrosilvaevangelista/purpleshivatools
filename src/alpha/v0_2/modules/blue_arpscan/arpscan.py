#Arp Scann

import subprocess
import socket
import time
import ipaddress
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import config as conf
from .progress import ProgressUpdater

class ArpScan:
    def __init__(self, ip_range, delay=0.1, verbose=False, timeout=2):
        self.ip_range = ip_range
        self.delay = delay
        self.verbose = verbose
        self.timeout = timeout
        self.alive_hosts = []
        self.system = platform.system().lower()
        
    def parse_ip_range(self, ip_range):
        """Parse diferentes formatos de range de IP"""
        try:
            # Se for uma rede CIDR (ex: 192.168.1.0/24)
            if '/' in ip_range:
                network = ipaddress.IPv4Network(ip_range, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            # Se for um range (ex: 192.168.1.1-192.168.1.254)
            elif '-' in ip_range:
                start_ip, end_ip = ip_range.split('-')
                start = ipaddress.IPv4Address(start_ip.strip())
                end = ipaddress.IPv4Address(end_ip.strip())
                
                ips = []
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                return ips
            
            # Se for um IP único
            else:
                ipaddress.IPv4Address(ip_range)  # Validar
                return [ip_range]
                
        except Exception as e:
            raise ValueError(f"Formato de IP inválido: {ip_range}. Use: IP único, range (1.1.1.1-1.1.1.10) ou CIDR (192.168.1.0/24)")

    def ping_host(self, ip):
        """Ping um host para verificar se está ativo"""
        try:
            if self.system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]
            
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout + 1)
            return result.returncode == 0
        except:
            return False

    def get_mac_address(self, ip):
        """Obter endereço MAC via ARP"""
        try:
            if self.system == "windows":
                # Windows: usar arp -a
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line and 'dynamic' in line.lower():
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:  # Formato XX-XX-XX-XX-XX-XX
                                    return part.replace('-', ':').upper()
            else:
                # Linux/Unix: usar arp
                result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                if ':' in mac and len(mac) == 17:
                                    return mac.upper()
        except:
            pass
        
        return "N/A"

    def get_hostname(self, ip):
        """Tentar resolver hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "N/A"

    def get_vendor_info(self, mac):
        """Obter informações do fabricante baseado no MAC (OUI)"""
        if mac == "N/A" or len(mac) < 8:
            return "Unknown"
        
        oui = mac[:8].replace(':', '').upper()
        
        # Pequeno banco de dados de OUIs comuns
        oui_db = {
            # Apple
            "001B63": "Apple", "3C07F4": "Apple", "B4B686": "Apple",
            "A8B1D4": "Apple", "28F076": "Apple", "F0D5BF": "Apple",

            # Parallels
            "001C42": "Parallels",

            # QEMU / KVM
            "525400": "QEMU/KVM",

            # VirtualBox
            "080027": "VirtualBox",

            # VMware
            "000C29": "VMware", "005056": "VMware", "001C14": "VMware", "000569": "VMware",

            # Cisco
            "001E68": "Cisco", "0050B6": "Cisco", "F87B20": "Cisco", "C83A35": "Cisco", "D4CAE1": "Cisco",

            # Dell
            "001A2F": "Dell", "842B2B": "Dell", "D4BED4": "Dell", "C85B76": "Dell", "F8B156": "Dell",

            # Samsung
            "001999": "Samsung", "30F772": "Samsung", "E4B2FB": "Samsung", "9C93E4": "Samsung", "8C7712": "Samsung",

            # Netgear
            "001E4C": "Netgear", "009027": "Netgear", "C40415": "Netgear", "A02BB8": "Netgear",

            # Belkin
            "001B2F": "Belkin", "944452": "Belkin", "EC1A59": "Belkin", "00022D": "Belkin",

            # TP-Link
            "001346": "TP-Link", "D850E6": "TP-Link", "2C3AE8": "TP-Link", "50BD5F": "TP-Link", "B07D43": "TP-Link",

            # HP
            "001F3F": "HP", "CC3E5F": "HP", "009C02": "HP", "F8BC12": "HP", "8CDE52": "HP",

            # Huawei
            "6C9CED": "Huawei", "D8B12A": "Huawei", "C8D15E": "Huawei",

            # Xiaomi
            "4C49E3": "Xiaomi", "D885DD": "Xiaomi", "FC640BA": "Xiaomi",

            # Intel
            "001B21": "Intel", "A037F1": "Intel", "F4CE46": "Intel",

            # ASUS
            "F8E71E": "ASUS", "AC220B": "ASUS", "A0F3C1": "ASUS",

            # LG
            "E8E5D6": "LG", "B8F6B1": "LG",

            # Realtek
            "00E04C": "Realtek", "F0DEF1": "Realtek"
        }
        
        return oui_db.get(oui[:6], "Unknown")

    def scan_host(self, ip, progress_updater=None):
        """Escanear um host específico"""
        try:
            if self.verbose:
                print(f"{conf.YELLOW}[>] Testando {ip}...{conf.RESET}")
            
            # Ping para verificar se host está ativo
            if self.ping_host(ip):
                mac = self.get_mac_address(ip)
                hostname = self.get_hostname(ip)
                vendor = self.get_vendor_info(mac)
                
                host_info = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'vendor': vendor,
                    'status': 'UP'
                }
                
                if self.verbose:
                    print(f"{conf.GREEN}[✓] Host ativo: {ip} | MAC: {mac} | Hostname: {hostname}{conf.RESET}")
                
                return host_info
            
            time.sleep(self.delay)
            
        except Exception as e:
            if self.verbose:
                print(f"{conf.RED}[!] Erro ao escanear {ip}: {e}{conf.RESET}")
        
        finally:
            if progress_updater:
                progress_updater.increment()
        
        return None

    def scan(self):
        """Executar o scan ARP completo"""
        start_time = time.time()
        
        try:
            # Parse do range de IPs
            ip_list = self.parse_ip_range(self.ip_range)
            total_ips = len(ip_list)
            
            print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
            print(f"{conf.PURPLE}{conf.BOLD} ARPSCAN - PURPLE SHIVA TOOLS {conf.RESET}")
            print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
            print(f"{conf.CYAN}Target Range: {conf.WHITE}{self.ip_range}{conf.RESET}")
            print(f"{conf.CYAN}Total IPs: {conf.WHITE}{total_ips}{conf.RESET}")
            print(f"{conf.CYAN}Delay: {conf.WHITE}{self.delay}s{conf.RESET}")
            print(f"{conf.CYAN}Timeout: {conf.WHITE}{self.timeout}s{conf.RESET}")
            print(f"{conf.PURPLE}{'='*60}{conf.RESET}\n")
            
            # Iniciar progress updater
            progress_updater = ProgressUpdater(total_ips)
            progress_updater.start()
            
            # Usar ThreadPoolExecutor para scan paralelo
            max_threads = min(50, total_ips)  # Limitar threads
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_ip = {
                    executor.submit(self.scan_host, ip, progress_updater): ip 
                    for ip in ip_list
                }
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        self.alive_hosts.append(result)
            
            # Parar progress updater
            progress_updater.stop()
            time.sleep(1)  # Aguardar última atualização
            
            # Resultado do scan
            end_time = time.time()
            duration = end_time - start_time
            
            # Exibir resultados
            self.print_results()
            
            return {
                'ip_range': self.ip_range,
                'total_ips': total_ips,
                'alive_hosts': self.alive_hosts,
                'alive_count': len(self.alive_hosts),
                'duration': duration
            }
            
        except KeyboardInterrupt:
            print(f"\n{conf.YELLOW}[!] Scan interrompido pelo usuário{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Erro durante o scan: {e}{conf.RESET}")
            raise

    def print_results(self):
        """Exibir resultados formatados"""
        if not self.alive_hosts:
            print(f"\n{conf.YELLOW}[!] Nenhum host ativo encontrado{conf.RESET}")
            return
        
        print(f"\n{conf.GREEN}{'='*80}{conf.RESET}")
        print(f"{conf.GREEN}{conf.BOLD} HOSTS ATIVOS ENCONTRADOS ({len(self.alive_hosts)}) {conf.RESET}")
        print(f"{conf.GREEN}{'='*80}{conf.RESET}")
        
        # Cabeçalho da tabela
        header = f"{'IP ADDRESS':<15} | {'MAC ADDRESS':<17} | {'HOSTNAME':<25} | {'VENDOR':<15}"
        print(f"{conf.PURPLE}{header}{conf.RESET}")
        print(f"{conf.PURPLE}{'-'*len(header)}{conf.RESET}")
        
        # Hosts encontrados
        for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x['ip'])):
            ip = host['ip']
            mac = host['mac']
            hostname = host['hostname'][:25] if host['hostname'] != "N/A" else "N/A"
            vendor = host['vendor'][:15]
            
            line = f"{conf.GREEN}{ip:<15}{conf.RESET} | {conf.CYAN}{mac:<17}{conf.RESET} | {conf.WHITE}{hostname:<25}{conf.RESET} | {conf.YELLOW}{vendor:<15}{conf.RESET}"
            print(line)
        
        print(f"{conf.GREEN}{'='*80}{conf.RESET}")
