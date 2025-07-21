#ICMP Network Scanner

import subprocess
import threading
import time
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules import config as conf
from .progress import ProgressUpdater

class PingSweep:
    def __init__(self, ip_range, delay=0.1, verbose=False, max_threads=50):
        """Initializes the ping sweep scanner"""
        self.ip_range = ip_range
        self.delay = delay
        self.verbose = verbose
        self.max_threads = max_threads
        self.active_hosts = []
        self.total_hosts = 0
        self.scanned_hosts = 0
        self.start_time = None
        self.lock = threading.Lock()

    def parse_ip_range(self):
        """Converts the IP range into a list of individual IPs"""
        ips = []
        
        try:
            # Check if it's CIDR notation (e.g., 192.168.1.0/24)
            if '/' in self.ip_range:
                network = ipaddress.ip_network(self.ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                
            # Check if it's a range (e.g., 192.168.1.1-192.168.1.100)
            elif '-' in self.ip_range:
                start_ip, end_ip = self.ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                    
            # Single IP
            else:
                # Validate if it is a valid IP
                ipaddress.ip_address(self.ip_range)
                ips = [self.ip_range]
                
        except Exception as e:
            raise ValueError(f"Invalid IP format: {e}")
            
        return ips

    def ping_host(self, ip):
        """Pings a specific host"""
        result = {
            'ip': ip,
            'status': 'down',
            'response_time': None,
            'hostname': None,
            'error': None
        }
        
        try:
            # Ping command based on the operating system
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            # Run the ping
            process = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=3
            )
            
            if process.returncode == 0:
                result['status'] = 'up'
                
                # Extract response time from output
                output = process.stdout.lower()
                if 'time=' in output:
                    time_part = output.split('time=')[1].split()[0]
                    try:
                        result['response_time'] = float(time_part.replace('ms', ''))
                    except:
                        result['response_time'] = 0
                
                # Attempt to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result['hostname'] = hostname
                except:
                    result['hostname'] = 'Unknown'
                    
            else:
                result['error'] = 'Host did not respond'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)
        
        # Apply delay if specified
        if self.delay > 0:
            time.sleep(self.delay)
            
        return result

    def scan_worker(self, ip):
        """Worker thread to scan an IP"""

        result = self.ping_host(ip)
        
        with self.lock:
            self.scanned_hosts += 1
            
            if result['status'] == 'up':
                self.active_hosts.append(result)
                
                if self.verbose:
                    hostname_info = f" ({result['hostname']})" if result['hostname'] and result['hostname'] != 'Unknown' else ""
                    time_info = f" - {result['response_time']:.2f}ms" if result['response_time'] else ""
                    print(f"\n{conf.GREEN}[✓] {result['ip']}{hostname_info}{time_info}{conf.RESET}")
            
            elif self.verbose and result['error']:
                print(f"\n{conf.RED}[✗] {result['ip']} - {result['error']}{conf.RESET}")
        
        return result

    def scan(self):
        """Executes the full ping sweep"""

        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} STARTING PING SWEEP {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        try:
            # Parse the IP range
            ip_list = self.parse_ip_range()
            self.total_hosts = len(ip_list)
            
            if self.total_hosts == 0:
                raise ValueError("No valid IP found in the specified range")
            
            print(f"\n{conf.YELLOW}IP Range: {conf.RESET}{self.ip_range}")
            print(f"{conf.YELLOW}Total hosts: {conf.RESET}{self.total_hosts}")
            print(f"{conf.YELLOW}Threads: {conf.RESET}{self.max_threads}")
            print(f"{conf.YELLOW}Delay: {conf.RESET}{self.delay}s")
            
            # Start progress
            progress = ProgressUpdater(self.total_hosts)
            progress.start()
            
            self.start_time = time.time()
            
            # Run scan with threads
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all tasks
                future_to_ip = {executor.submit(self.scan_worker, ip): ip for ip in ip_list}
                
                # Process results as they complete
                for future in as_completed(future_to_ip):
                    try:
                        result = future.result()
                        progress.increment()
                    except Exception as e:
                        ip = future_to_ip[future]
                        if self.verbose:
                            print(f"\n{conf.RED}[!] Error scanning {ip}: {e}{conf.RESET}")
            
            # Stop progress
            progress.stop()
            
            # Calculate duration
            duration = time.time() - self.start_time
            
            # Final results
            print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
            print(f"{conf.PURPLE}{conf.BOLD} PING SWEEP RESULTS {conf.RESET}")
            print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
            
            print(f"\n{conf.YELLOW}Hosts scanned: {conf.RESET}{self.scanned_hosts}")
            print(f"{conf.GREEN}Active hosts: {conf.RESET}{len(self.active_hosts)}")
            print(f"{conf.YELLOW}Duration: {conf.RESET}{duration:.2f}s")
            
            if self.active_hosts:
                print(f"\n{conf.GREEN}{conf.BOLD}ACTIVE HOSTS FOUND:{conf.RESET}")
                print(f"{conf.GREEN}{'='*40}{conf.RESET}")
                
                for host in sorted(self.active_hosts, key=lambda x: ipaddress.ip_address(x['ip'])):
                    hostname_info = f" | {host['hostname']}" if host['hostname'] and host['hostname'] != 'Unknown' else ""
                    time_info = f" | {host['response_time']:.2f}ms" if host['response_time'] else ""
                    print(f"{conf.GREEN}  {host['ip']}{hostname_info}{time_info}{conf.RESET}")
            else:
                print(f"\n{conf.RED}No active hosts found in the specified range.{conf.RESET}")
            
            # Return structured results
            return {
                'ip_range': self.ip_range,
                'total_hosts': self.total_hosts,
                'scanned_hosts': self.scanned_hosts,
                'active_hosts': self.active_hosts,
                'active_count': len(self.active_hosts),
                'duration': duration,
                'success_rate': (len(self.active_hosts) / self.total_hosts) * 100 if self.total_hosts > 0 else 0
            }
            
        except KeyboardInterrupt:
            progress.stop() if 'progress' in locals() else None
            print(f"\n{conf.YELLOW}[!] Scan interrupted by user{conf.RESET}")
            return None
            
        except Exception as e:
            progress.stop() if 'progress' in locals() else None
            print(f"\n{conf.RED}[!] Error during scan: {e}{conf.RESET}")
            raise

    def quick_scan(self, top_hosts=10):
        """Executes a quick scan of the first N hosts"""
        
        print(f"\n{conf.YELLOW}[i] Running quick scan of first {top_hosts} hosts...{conf.RESET}")
        
        original_max_threads = self.max_threads
        self.max_threads = min(top_hosts, 20)  # Limit threads for quick scan
        
        try:
            ip_list = self.parse_ip_range()[:top_hosts]
            self.total_hosts = len(ip_list)
            
            results = []
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(self.ping_host, ip) for ip in ip_list]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result['status'] == 'up':
                        results.append(result)
            
            print(f"{conf.GREEN}[✓] Quick scan complete: {len(results)} active hosts{conf.RESET}")
            return results
            
        finally:
            self.max_threads = original_max_threads
