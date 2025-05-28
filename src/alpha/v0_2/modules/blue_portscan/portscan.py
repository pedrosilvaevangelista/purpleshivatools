# Port Scanner

import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from .progress import ProgressUpdater
import config as conf

class PortScan:
    def __init__(self, ip: str, port_range: str, delay: float = 0.01, verbose: bool = False, threads: int = 100):
        self.ip = ip
        self.port_range = port_range
        self.delay = delay
        self.verbose = verbose
        self.threads = min(threads, 200)  # Limita máximo de threads
        self.open_ports = []
        self.lock = threading.Lock()
        
        # Dicionário de serviços comuns
        self.common_services = {
    7:"Echo", 19:"Chargen", 20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 37:"Time", 42:"WINS", 43:"WHOIS", 
    49:"TACACS", 53:"DNS", 67:"DHCP-Server", 68:"DHCP-Client", 69:"TFTP", 70:"Gopher", 79:"Finger", 80:"HTTP", 88:"Kerberos", 
    102:"MSExchange", 110:"POP3", 111:"RPC", 113:"Ident", 119:"NNTP", 123:"NTP", 135:"MSRPC", 137:"NetBIOS-NS", 138:"NetBIOS-DGM", 
    139:"NetBIOS-SSN", 143:"IMAP", 161:"SNMP", 162:"SNMP-Trap", 177:"XDMCP", 179:"BGP", 194:"IRC", 199:"SMUX", 201:"AppleTalk", 
    264:"BGMP", 318:"TSP", 381:"HP-OpenView", 383:"HP-OpenView", 389:"LDAP", 411:"DirectConnect", 412:"DirectConnect", 427:"SLP", 
    443:"HTTPS", 445:"SMB", 464:"Kerberos", 465:"SMTPS", 497:"Dantz", 500:"IPSec", 512:"rexec", 513:"rlogin", 514:"syslog", 
    515:"LPD", 520:"RIP", 521:"RIPng", 540:"UUCP", 548:"AFP", 554:"RTSP", 563:"NNTPS", 587:"SMTP-Submission", 591:"FileMaker", 
    593:"MS-RPC", 631:"IPP", 636:"LDAPS", 639:"MSDP", 646:"LDP", 691:"MS-Exchange", 860:"iSCSI", 873:"rsync", 902:"VMware-Server", 
    989:"FTPS-DATA", 990:"FTPS", 993:"IMAPS", 995:"POP3S", 1025:"MS-RPC", 1026:"MS-RPC", 1027:"MS-RPC", 1028:"MS-RPC", 1029:"MS-RPC",
    1080:"SOCKS", 1194:"OpenVPN", 1214:"Kazaa", 1241:"Nessus", 1311:"Dell-OpenManage", 1337:"WASTE", 1433:"MS-SQL", 1434:"MS-SQL-Monitor",
    1512:"WINS", 1521:"Oracle", 1589:"Cisco-VQP", 1720:"H.323", 1723:"PPTP", 1725:"Steam", 1755:"MS-Media-Server", 1812:"RADIUS",
    1813:"RADIUS-Accounting", 1863:"MSN", 1900:"UPnP", 2000:"SCCP", 2049:"NFS", 2082:"cPanel", 2083:"cPanel-SSL", 2100:"Oracle-XDB",
    2222:"DirectAdmin", 2302:"ArmA", 2483:"Oracle-DB", 2484:"Oracle-DB-SSL", 2745:"Bagle", 2967:"Symantec-AV", 3000:"Ruby-on-Rails",
    3050:"Interbase", 3074:"Xbox-Live", 3128:"Squid", 3222:"GLBP", 3260:"iSCSI", 3306:"MySQL", 3389:"RDP", 3689:"DAAP", 3690:"SVN",
    3724:"WoW", 3784:"Ventrilo", 3785:"Ventrilo", 4333:"mSQL", 4444:"Metasploit", 4500:"IPSec-NAT-T", 4567:"Sinatra", 4662:"eMule",
    4664:"Google-Desktop", 4899:"Radmin", 5000:"UPnP", 5001:"Slingbox", 5004:"RTP", 5005:"RTP", 5050:"Yahoo-Messenger", 5060:"SIP",
    5190:"AIM", 5222:"XMPP", 5223:"XMPP-SSL", 5269:"XMPP-Server", 5353:"mDNS", 5432:"PostgreSQL", 5500:"VNC", 5555:"Freeciv",
    5631:"pcAnywhere", 5666:"Nagios", 5800:"VNC-HTTP", 5900:"VNC", 6000:"X11", 6001:"X11", 6112:"Battle.net", 6129:"DameWare",
    6257:"WinMX", 6346:"Gnutella", 6379:"Redis", 6502:"Net2Display", 6566:"SANE", 6588:"AnalogX", 6665:"IRC", 6666:"IRC", 6667:"IRC",
    6668:"IRC", 6669:"IRC", 6679:"IRC-SSL", 6697:"IRC-SSL", 6881:"BitTorrent", 6882:"BitTorrent", 6883:"BitTorrent", 6884:"BitTorrent",
    6885:"BitTorrent", 6886:"BitTorrent", 6887:"BitTorrent", 6888:"BitTorrent", 6889:"BitTorrent", 6890:"BitTorrent", 6891:"BitTorrent",
    6901:"BitTorrent", 6969:"BitTorrent", 6970:"QuickTime", 7212:"GhostSurf", 7648:"CU-SeeMe", 8000:"HTTP-Alt", 8008:"HTTP-Alt",
    8080:"HTTP-Proxy", 8081:"HTTP-Proxy", 8088:"Radan-HTTP", 8090:"HTTP-Alt", 8118:"Privoxy", 8200:"VMware", 8222:"VMware", 8291:"Winbox",
    8292:"Winbox", 8333:"Bitcoin", 8400:"Commvault", 8443:"HTTPS-Alt", 8500:"Adobe-ColdFusion", 8767:"TeamSpeak", 8888:"Sun-Answerbook",
    9000:"SonarQube", 9001:"Tor", 9043:"WebSphere", 9090:"WebSM", 9091:"Openfire", 9100:"JetDirect", 9119:"MXit", 9293:"Sony-PS3",
    9418:"Git", 9535:"mDNS", 9800:"WebDAV", 9898:"Dabber", 9988:"Rbot", 9999:"Urchin", 10000:"Webmin", 10050:"Zabbix", 10051:"Zabbix",
    10113:"NetIQ", 10114:"NetIQ", 10115:"NetIQ", 10116:"NetIQ", 11371:"OpenPGP", 12035:"SecondLife", 12036:"SecondLife", 12345:"NetBus",
    13720:"NetBackup", 13721:"NetBackup", 14567:"Battlefield", 15118:"Dipnet", 19226:"AdminSecure", 19638:"Ensim", 20000:"DNP3",
    24800:"Synergy", 25999:"Xfire", 27015:"Steam", 27017:"MongoDB", 27018:"MongoDB", 27374:"Sub7", 28960:"Call-of-Duty", 31337:"BackOrifice",
    33434:"Traceroute"
}

    def _parse_port_range(self):
        """Parse port range string into start and end ports"""
        try:
            if '-' in self.port_range:
                start_port, end_port = map(int, self.port_range.split('-'))
            else:
                # Single port
                start_port = end_port = int(self.port_range)
        except ValueError:
            raise ValueError(f"Port range inválido: '{self.port_range}'. Use formato 'início-fim' ou porta única.")
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Intervalo de portas deve estar entre 1 e 65535 e início ≤ fim.")
        
        return start_port, end_port

    def _identify_service(self, port):
        """Identify service running on port"""
        service = self.common_services.get(port, "Unknown")
        
        # Tenta identificar serviço através de banner grabbing (opcional)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((self.ip, port))
                
                # Tenta receber banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        # Identifica alguns serviços por banner
                        banner_lower = banner.lower()
                        if 'ssh' in banner_lower:
                            service = f"SSH ({banner[:50]}...)" if len(banner) > 50 else f"SSH ({banner})"
                        elif 'ftp' in banner_lower:
                            service = f"FTP ({banner[:50]}...)" if len(banner) > 50 else f"FTP ({banner})"
                        elif 'http' in banner_lower or 'server:' in banner_lower:
                            service = f"HTTP ({banner[:50]}...)" if len(banner) > 50 else f"HTTP ({banner})"
                        elif banner and service == "Unknown":
                            service = f"Unknown ({banner[:30]}...)" if len(banner) > 30 else f"Unknown ({banner})"
                except:
                    pass  # Se não conseguir ler banner, usa identificação por porta
                    
        except:
            pass  # Se não conseguir conectar, usa identificação por porta
            
        return service

    def _scan_port(self, port, progress):
        """Scan a single port with service identification"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  # Timeout reduzido para 1 segundo
                result = sock.connect_ex((self.ip, port))
                
                if result == 0:
                    service = self._identify_service(port)
                    port_info = {
                        'port': port,
                        'service': service,
                        'status': 'open'
                    }
                    
                    with self.lock:
                        self.open_ports.append(port_info)
                        if self.verbose:
                            print(f"\n{conf.GREEN}[+] Porta {port} ABERTA - {service}{conf.RESET}")
                    
                    return True
                else:
                    if self.verbose:
                        print(f"\n{conf.RED}[-] Porta {port} fechada{conf.RESET}")
                    return False
                    
        except Exception as e:
            if self.verbose:
                print(f"{conf.YELLOW}[!] Erro escaneando porta {port}: {e}{conf.RESET}")
            return False
        finally:
            progress.increment()
            if self.delay > 0:
                time.sleep(self.delay)

    def scan(self):
        """Execute port scan with threading"""
        start_port, end_port = self._parse_port_range()
        ports = list(range(start_port, end_port + 1))
        total_ports = len(ports)
        
        print(f"\n{conf.CYAN}[*] Iniciando scan de portas em {self.ip}{conf.RESET}")
        print(f"{conf.CYAN}[*] Intervalo: {start_port}-{end_port} ({total_ports} portas){conf.RESET}")
        print(f"{conf.CYAN}[*] Threads: {self.threads}{conf.RESET}")
        print(f"{conf.CYAN}[*] Delay: {self.delay}s{conf.RESET}")
        print(f"{conf.CYAN}[*] Identificação de serviços: Ativada{conf.RESET}\n")
        
        # Inicia monitor de progresso
        progress = ProgressUpdater(total_tasks=total_ports)
        progress.start()
        
        start_time = time.time()
        
        try:
            # Usa ThreadPoolExecutor para paralelização
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submete todas as tarefas
                future_to_port = {
                    executor.submit(self._scan_port, port, progress): port 
                    for port in ports
                }
                
                # Aguarda conclusão de todas as tarefas
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        future.result()
                    except Exception as e:
                        if self.verbose:
                            print(f"{conf.YELLOW}[!] Erro na thread para porta {port}: {e}{conf.RESET}")
                            
        except KeyboardInterrupt:
            print(f"\n\n{conf.YELLOW}[!] Scan interrompido pelo usuário{conf.RESET}")
        finally:
            progress.stop()
            
        duration = time.time() - start_time
        
        # Ordena portas abertas por número da porta
        self.open_ports.sort(key=lambda x: x['port'])
        
        # Resultados finais - só mostra no final
        self._print_results(total_ports, duration)
        
        return {
            "ip": self.ip,
            "total_ports": total_ports,
            "open_ports": self.open_ports,
            "duration": duration
        }

    def _print_results(self, total_ports, duration):
        """Print final results in a clean format"""
        print(f"\n{conf.PURPLE}{'='*80}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD}                    RESULTADO DO SCAN DE PORTAS                    {conf.RESET}")
        print(f"{conf.PURPLE}{'='*80}{conf.RESET}")
        
        print(f"🎯 {conf.BOLD}Alvo:{conf.RESET} {conf.GREEN}{self.ip}{conf.RESET}")
        print(f"📊 {conf.BOLD}Portas escaneadas:{conf.RESET} {conf.GREEN}{total_ports:,}{conf.RESET}")
        print(f"⚡ {conf.BOLD}Duração:{conf.RESET} {conf.GREEN}{duration:.2f}s{conf.RESET}")
        print(f"🔍 {conf.BOLD}Threads utilizadas:{conf.RESET} {conf.GREEN}{self.threads}{conf.RESET}")
        print(f"🔓 {conf.BOLD}Portas abertas encontradas:{conf.RESET} {conf.GREEN}{len(self.open_ports)}{conf.RESET}")
        
        if self.open_ports:
            print(f"\n{conf.PURPLE}{'─'*80}{conf.RESET}")
            print(f"{conf.PURPLE}{conf.BOLD}                      PORTAS ABERTAS                               {conf.RESET}")
            print(f"{conf.PURPLE}{'─'*80}{conf.RESET}")
            print(f"{'PORTA':<8} {'ESTADO':<10} {'SERVIÇO':<62}")
            print(f"{conf.PURPLE}{'─'*80}{conf.RESET}")
            
            for port_info in self.open_ports:
                port = port_info['port']
                service = port_info['service']
                status = "ABERTA"
                
                # Trunca serviço se muito longo
                if len(service) > 60:
                    service = service[:57] + "..."
                
                print(f"{conf.GREEN}{port:<8}{conf.RESET} "
                      f"{conf.GREEN}{status:<10}{conf.RESET} "
                      f"{conf.CYAN}{service:<62}{conf.RESET}")
            
            print(f"{conf.PURPLE}{'─'*80}{conf.RESET}")
            
            # Resumo por tipo de serviço
            services_count = {}
            for port_info in self.open_ports:
                service_name = port_info['service'].split('(')[0].strip()
                services_count[service_name] = services_count.get(service_name, 0) + 1
            
            if len(services_count) > 1:
                print(f"\n{conf.BOLD}📈 Resumo por serviço:{conf.RESET}")
                for service, count in sorted(services_count.items()):
                    print(f"   • {conf.CYAN}{service}{conf.RESET}: {conf.GREEN}{count} porta(s){conf.RESET}")
        else:
            print(f"\n{conf.YELLOW}❌ Nenhuma porta aberta encontrada no intervalo especificado{conf.RESET}")
            print(f"{conf.YELLOW}   Tente um intervalo maior ou verifique se o host está ativo{conf.RESET}")
        
        print(f"\n{conf.PURPLE}{'='*80}{conf.RESET}")
        
        # Estatísticas de performance
        ports_per_second = total_ports / duration if duration > 0 else 0
        print(f"⚡ {conf.BOLD}Performance:{conf.RESET} {conf.GREEN}{ports_per_second:.0f} portas/segundo{conf.RESET}")
        print(f"{conf.PURPLE}{'='*80}{conf.RESET}")