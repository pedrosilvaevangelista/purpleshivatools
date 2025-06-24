# pingsweep scanner
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
        """
        Inicializa o scanner de ping sweep
        
        Args:
            ip_range (str): Range de IPs (ex: "192.168.1.0/24" ou "192.168.1.1-192.168.1.100")
            delay (float): Delay entre pings em segundos
            verbose (bool): Modo verbose para output detalhado
            max_threads (int): Número máximo de threads
        """
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
        """
        Converte o range de IPs em lista de IPs individuais
        
        Returns:
            list: Lista de endereços IP para escanear
        """
        ips = []
        
        try:
            # Verifica se é CIDR (ex: 192.168.1.0/24)
            if '/' in self.ip_range:
                network = ipaddress.ip_network(self.ip_range, strict=False)
                ips = [str(ip) for ip in network.hosts()]
                
            # Verifica se é range (ex: 192.168.1.1-192.168.1.100)
            elif '-' in self.ip_range:
                start_ip, end_ip = self.ip_range.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    ips.append(str(current))
                    current += 1
                    
            # IP único
            else:
                # Valida se é um IP válido
                ipaddress.ip_address(self.ip_range)
                ips = [self.ip_range]
                
        except Exception as e:
            raise ValueError(f"Formato de IP inválido: {e}")
            
        return ips

    def ping_host(self, ip):
        """
        Executa ping em um host específico
        
        Args:
            ip (str): Endereço IP para pingar
            
        Returns:
            dict: Resultado do ping com informações do host
        """
        result = {
            'ip': ip,
            'status': 'down',
            'response_time': None,
            'hostname': None,
            'error': None
        }
        
        try:
            # Comando ping baseado no sistema operacional
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            # Executa o ping
            process = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=3
            )
            
            if process.returncode == 0:
                result['status'] = 'up'
                
                # Extrai tempo de resposta do output
                output = process.stdout.lower()
                if 'time=' in output:
                    time_part = output.split('time=')[1].split()[0]
                    try:
                        result['response_time'] = float(time_part.replace('ms', ''))
                    except:
                        result['response_time'] = 0
                
                # Tenta resolver o hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    result['hostname'] = hostname
                except:
                    result['hostname'] = 'Unknown'
                    
            else:
                result['error'] = 'Host não responde'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)
        
        # Aplicar delay se especificado
        if self.delay > 0:
            time.sleep(self.delay)
            
        return result

    def scan_worker(self, ip):
        """
        Worker thread para escanear um IP
        
        Args:
            ip (str): IP para escanear
            
        Returns:
            dict: Resultado do scan
        """
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
        """
        Executa o ping sweep completo
        
        Returns:
            dict: Resultados completos do scan
        """
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO PING SWEEP {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        try:
            # Parse do range de IPs
            ip_list = self.parse_ip_range()
            self.total_hosts = len(ip_list)
            
            if self.total_hosts == 0:
                raise ValueError("Nenhum IP válido encontrado no range especificado")
            
            print(f"\n{conf.YELLOW}Range de IPs: {conf.RESET}{self.ip_range}")
            print(f"{conf.YELLOW}Total de hosts: {conf.RESET}{self.total_hosts}")
            print(f"{conf.YELLOW}Threads: {conf.RESET}{self.max_threads}")
            print(f"{conf.YELLOW}Delay: {conf.RESET}{self.delay}s")
            
            # Inicia progresso
            progress = ProgressUpdater(self.total_hosts)
            progress.start()
            
            self.start_time = time.time()
            
            # Executa scan com threads
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submete todas as tarefas
                future_to_ip = {executor.submit(self.scan_worker, ip): ip for ip in ip_list}
                
                # Processa resultados conforme completam
                for future in as_completed(future_to_ip):
                    try:
                        result = future.result()
                        progress.increment()
                    except Exception as e:
                        ip = future_to_ip[future]
                        if self.verbose:
                            print(f"\n{conf.RED}[!] Erro escaneando {ip}: {e}{conf.RESET}")
            
            # Para o progresso
            progress.stop()
            
            # Calcula duração
            duration = time.time() - self.start_time
            
            # Resultados finais
            print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
            print(f"{conf.PURPLE}{conf.BOLD} RESULTADOS DO PING SWEEP {conf.RESET}")
            print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
            
            print(f"\n{conf.YELLOW}Hosts escaneados: {conf.RESET}{self.scanned_hosts}")
            print(f"{conf.GREEN}Hosts ativos: {conf.RESET}{len(self.active_hosts)}")
            print(f"{conf.YELLOW}Duração: {conf.RESET}{duration:.2f}s")
            
            if self.active_hosts:
                print(f"\n{conf.GREEN}{conf.BOLD}HOSTS ATIVOS ENCONTRADOS:{conf.RESET}")
                print(f"{conf.GREEN}{'='*40}{conf.RESET}")
                
                for host in sorted(self.active_hosts, key=lambda x: ipaddress.ip_address(x['ip'])):
                    hostname_info = f" | {host['hostname']}" if host['hostname'] and host['hostname'] != 'Unknown' else ""
                    time_info = f" | {host['response_time']:.2f}ms" if host['response_time'] else ""
                    print(f"{conf.GREEN}  {host['ip']}{hostname_info}{time_info}{conf.RESET}")
            else:
                print(f"\n{conf.RED}Nenhum host ativo encontrado no range especificado.{conf.RESET}")
            
            # Retorna resultados estruturados
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
            print(f"\n{conf.YELLOW}[!] Scan interrompido pelo usuário{conf.RESET}")
            return None
            
        except Exception as e:
            progress.stop() if 'progress' in locals() else None
            print(f"\n{conf.RED}[!] Erro durante o scan: {e}{conf.RESET}")
            raise

    def quick_scan(self, top_hosts=10):
        """
        Executa um scan rápido dos primeiros N hosts
        
        Args:
            top_hosts (int): Número de hosts para escanear rapidamente
            
        Returns:
            dict: Resultados do scan rápido
        """
        print(f"\n{conf.YELLOW}[i] Executando scan rápido dos primeiros {top_hosts} hosts...{conf.RESET}")
        
        original_max_threads = self.max_threads
        self.max_threads = min(top_hosts, 20)  # Limita threads para scan rápido
        
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
            
            print(f"{conf.GREEN}[✓] Scan rápido concluído: {len(results)} hosts ativos{conf.RESET}")
            return results
            
        finally:
            self.max_threads = original_max_threads