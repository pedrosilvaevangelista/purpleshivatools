# ARP Network Scanner

import subprocess
import socket
import time
import ipaddress
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import os
from modules import config as conf
from .progress import ProgressUpdater

class ArpScan:
    def __init__(self, ip_range, delay=0.1, verbose=False, timeout=2):
        self.ip_range = ip_range
        self.delay = delay
        self.verbose = verbose
        self.timeout = timeout
        self.alive_hosts = []
        self.system = platform.system().lower()
        self.oui_db = self.load_oui_database()
        
    def load_oui_database(self):
        """Load OUI database from CSV file"""
        oui_db = {}
        csv_path = conf.OuiCsv
        
        try:
            if not os.path.exists(csv_path):
                print(f"{conf.YELLOW}[!] OUI CSV file not found at {csv_path}{conf.RESET}")
                return oui_db
            
            with open(csv_path, mode='r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    mac_prefix = row['Assignment'].replace(':', '').upper()[:6]
                    if mac_prefix:
                        oui_db[mac_prefix] = row['Organization Name']
                        
            if self.verbose:
                print(f"{conf.GREEN}[+] OUI database loaded with {len(oui_db)} entries{conf.RESET}")
                
        except Exception as e:
            print(f"{conf.RED}[!] Error loading OUI CSV file: {e}{conf.RESET}")
            
        return oui_db

    def parse_ip_range(self, ip_range):
        """Parse different IP range formats"""
        try:
            if '/' in ip_range:
                network = ipaddress.IPv4Network(ip_range, strict=False)
                return [str(ip) for ip in network.hosts()]
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
            else:
                ipaddress.IPv4Address(ip_range)
                return [ip_range]
                
        except Exception as e:
            raise ValueError(f"Invalid IP format: {ip_range}. Use: single IP, range (1.1.1.1-1.1.1.10), or CIDR (192.168.1.0/24)")

    def send_arp_request(self, ip):
        """Send a direct ARP request"""
        try:
            if self.system == "windows":
                # On Windows, use arp -a to check the ARP table
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line and 'dynamic' in line.lower():
                            return True
            else:
                # On Linux, use arping if available
                try:
                    result = subprocess.run(["arping", "-c", "1", "-w", str(self.timeout), ip], 
                                          capture_output=True, text=True, timeout=self.timeout + 1)
                    return result.returncode == 0
                except FileNotFoundError:
                    # If arping is not available, fallback to checking ARP table
                    result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if ip in line and not line.strip().endswith("incomplete"):
                                return True
        except:
            pass
        return False

    def get_mac_address(self, ip):
        """Get MAC address via ARP"""
        try:
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
        """Attempt to resolve hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "N/A"

    def get_vendor_info(self, mac):
        """Get vendor info based on MAC (OUI)"""
        if mac == "N/A" or len(mac) < 8:
            return "Unknown"
        
        oui = mac[:8].replace(':', '').upper()
        vendor = self.oui_db.get(oui[:6], "Unknown")        
        return vendor

    def scan_host(self, ip, progress_updater=None):
        """Scan a single host using ARP only"""
        try:
            if self.verbose:
                print(f"{conf.YELLOW}[>] Testing {ip}...{conf.RESET}")
            
            if self.send_arp_request(ip):
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
                    print(f"{conf.GREEN}[✓] Active host: {ip} | MAC: {mac} | Hostname: {hostname}{conf.RESET}")
                
                return host_info
            
            time.sleep(self.delay)
            
        except Exception as e:
            if self.verbose:
                print(f"{conf.RED}[!] Error scanning {ip}: {e}{conf.RESET}")
        
        finally:
            if progress_updater:
                progress_updater.increment()
        
        return None

    def scan(self):
        """Run the full ARP scan"""
        start_time = time.time()
        
        try:
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
            
            progress_updater = ProgressUpdater(total_ips, silent=self.verbose)
            progress_updater.start()
            
            max_threads = min(50, total_ips)
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_ip = {
                    executor.submit(self.scan_host, ip, progress_updater): ip 
                    for ip in ip_list
                }
                
                for future in as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        self.alive_hosts.append(result)
            
            progress_updater.stop()
            
            if self.verbose:
                progress_info = progress_updater.get_progress_info()
                print(f"\n{conf.GREEN}[✓] Scan completed: {progress_info['completed']}/{progress_info['total']} IPs scanned in {progress_info['elapsed']}{conf.RESET}")
            
            time.sleep(1)
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.print_results()
            
            return {
                'ip_range': self.ip_range,
                'total_ips': total_ips,
                'alive_hosts': self.alive_hosts,
                'alive_count': len(self.alive_hosts),
                'duration': duration
            }
        
        except KeyboardInterrupt:
            print(f"\n{conf.YELLOW}[!] Scan interrupted by user{conf.RESET}")
        except Exception as e:
            print(f"{conf.RED}[!] Error during scan: {e}{conf.RESET}")
            raise

    def print_results(self):
        """Display formatted results"""
        if not self.alive_hosts:
            print(f"\n{conf.YELLOW}[!] No active hosts found{conf.RESET}")
            return
        
        print(f"\n{conf.GREEN}{'='*80}{conf.RESET}")
        print(f"{conf.GREEN}{conf.BOLD} ACTIVE HOSTS FOUND ({len(self.alive_hosts)}) {conf.RESET}")
        print(f"{conf.GREEN}{'='*80}{conf.RESET}")
        
        header = f"{'IP ADDRESS':<15} | {'MAC ADDRESS':<17} | {'VENDOR':<35}"
        print(f"{conf.PURPLE}{header}{conf.RESET}")
        print(f"{conf.PURPLE}{'-'*len(header)}{conf.RESET}")
        
        for host in sorted(self.alive_hosts, key=lambda x: ipaddress.IPv4Address(x['ip'])):
            ip = host['ip']
            mac = host['mac']
            vendor = host['vendor']
            
            line = f"{conf.GREEN}{ip:<15}{conf.RESET} | {conf.CYAN}{mac:<17}{conf.RESET} | {conf.YELLOW}{vendor}{conf.RESET}"
            print(line)
        
        print(f"{conf.GREEN}{'='*80}{conf.RESET}")
