# enumeração de SMB
import socket
import struct
import time
from datetime import datetime
import subprocess
import re
import config as conf
from .progress import ProgressUpdater

class SMBEnumerator:
    def __init__(self, target_ip, timeout=5, verbose=False):
        self.target_ip = target_ip
        self.timeout = timeout
        self.verbose = verbose
        self.results = {
            "target_ip": target_ip,
            "timestamp": datetime.now().isoformat(),
            "netbios_info": {},
            "smb_info": {},
            "shares": [],
            "os_info": {},
            "security_info": {},
            "sessions": [],
            "open_ports": [],
            "errors": []
        }
        
    def log_verbose(self, message):
        if self.verbose:
            print(f"{conf.CYAN}[INFO] {message}{conf.RESET}")
            
    def log_error(self, message):
        error_msg = f"[ERROR] {message}"
        print(f"{conf.RED}{error_msg}{conf.RESET}")
        self.results["errors"].append(error_msg)
        
    def check_port(self, port):
        """Verifica se uma porta está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            return result == 0
        except Exception as e:
            return False
            
    def netbios_name_query(self):
        """Enumeração NetBIOS Name Service (porta 137)"""
        self.log_verbose("Iniciando consulta NetBIOS...")
        
        try:
            # Query NetBIOS usando nmblookup se disponível
            cmd = ["nmblookup", "-A", self.target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                netbios_data = self.parse_nmblookup_output(result.stdout)
                self.results["netbios_info"] = netbios_data
                self.log_verbose(f"NetBIOS info coletada: {len(netbios_data)} entradas")
            else:
                self.log_error("nmblookup não disponível ou falhou")
                
        except subprocess.TimeoutExpired:
            self.log_error("Timeout na consulta NetBIOS")
        except FileNotFoundError:
            self.log_verbose("nmblookup não encontrado, tentando método alternativo")
            self.netbios_raw_query()
        except Exception as e:
            self.log_error(f"Erro na consulta NetBIOS: {e}")
            
    def parse_nmblookup_output(self, output):
        """Parse da saída do nmblookup"""
        netbios_info = {}
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if '<' in line and '>' in line:
                # Formato: NOME            <CODE> -         B <ACTIVE>
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    code_match = re.search(r'<(\w+)>', line)
                    if code_match:
                        code = code_match.group(1)
                        status = "ACTIVE" if "ACTIVE" in line else "INACTIVE"
                        
                        netbios_info[name] = {
                            "code": code,
                            "status": status,
                            "type": self.get_netbios_type(code)
                        }
        return netbios_info
        
    def get_netbios_type(self, code):
        """Retorna o tipo do código NetBIOS"""
        types = {
            "00": "Workstation Service",
            "03": "Messenger Service",
            "06": "RAS Server Service",
            "1F": "NetDDE Service",
            "20": "File Server Service",
            "21": "RAS Client Service",
            "1D": "Master Browser",
            "1B": "Domain Master Browser"
        }
        return types.get(code, f"Unknown ({code})")
        
    def netbios_raw_query(self):
        """Query NetBIOS raw quando nmblookup não está disponível"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Construir query NetBIOS
            query = b'\x00\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
            
            sock.sendto(query, (self.target_ip, 137))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            # Parse básico da resposta
            if len(response) > 56:
                self.results["netbios_info"]["raw_response"] = "NetBIOS resposta recebida"
                self.log_verbose("NetBIOS raw query bem-sucedida")
            
        except Exception as e:
            self.log_verbose(f"NetBIOS raw query falhou: {e}")
            
    def enumerate_smb_shares(self):
        """Enumera compartilhamentos SMB"""
        self.log_verbose("Enumerando compartilhamentos SMB...")
        
        try:
            # Usar smbclient se disponível
            cmd = ["smbclient", "-L", self.target_ip, "-N"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout * 2)
            
            if result.returncode == 0:
                shares = self.parse_smbclient_output(result.stdout)
                self.results["shares"] = shares
                self.log_verbose(f"Compartilhamentos encontrados: {len(shares)}")
            else:
                self.log_verbose("smbclient falhou ou sem compartilhamentos")
                
        except subprocess.TimeoutExpired:
            self.log_error("Timeout na enumeração de compartilhamentos")
        except FileNotFoundError:
            self.log_verbose("smbclient não encontrado")
        except Exception as e:
            self.log_error(f"Erro na enumeração SMB: {e}")
            
    def parse_smbclient_output(self, output):
        """Parse da saída do smbclient"""
        shares = []
        lines = output.split('\n')
        in_shares_section = False
        
        for line in lines:
            line = line.strip()
            
            if "Sharename" in line and "Type" in line:
                in_shares_section = True
                continue
                
            if in_shares_section and line and not line.startswith('-'):
                if line.startswith('SMB') or line.startswith('session'):
                    break
                    
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1] if len(parts) > 1 else "Unknown"
                    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                    
                    shares.append({
                        "name": share_name,
                        "type": share_type,
                        "comment": comment
                    })
                    
        return shares
        
    def get_smb_version(self):
        """Detecta versão do protocolo SMB"""
        self.log_verbose("Detectando versão SMB...")
        
        try:
            # Usar enum4linux se disponível
            cmd = ["enum4linux", "-a", self.target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout * 3)
            
            if result.returncode == 0:
                smb_info = self.parse_enum4linux_output(result.stdout)
                self.results["smb_info"] = smb_info
                self.log_verbose("Informações SMB coletadas via enum4linux")
            else:
                self.basic_smb_detection()
                
        except subprocess.TimeoutExpired:
            self.log_error("Timeout na detecção SMB")
        except FileNotFoundError:
            self.log_verbose("enum4linux não encontrado, usando detecção básica")
            self.basic_smb_detection()
        except Exception as e:
            self.log_error(f"Erro na detecção SMB: {e}")
            
    def parse_enum4linux_output(self, output):
        """Parse da saída do enum4linux"""
        smb_info = {
            "os_version": "",
            "smb_version": "",
            "domain": "",
            "workgroup": "",
            "server_type": ""
        }
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            if "OS:" in line:
                os_match = re.search(r'OS:\s*(.+)', line)
                if os_match:
                    smb_info["os_version"] = os_match.group(1).strip()
                    
            elif "Server:" in line:
                server_match = re.search(r'Server:\s*(.+)', line)
                if server_match:
                    smb_info["smb_version"] = server_match.group(1).strip()
                    
            elif "Domain:" in line:
                domain_match = re.search(r'Domain:\s*(.+)', line)
                if domain_match:
                    smb_info["domain"] = domain_match.group(1).strip()
                    
            elif "Workgroup:" in line:
                wg_match = re.search(r'Workgroup:\s*(.+)', line)
                if wg_match:
                    smb_info["workgroup"] = wg_match.group(1).strip()
                    
        return smb_info
        
    def basic_smb_detection(self):
        """Detecção básica SMB sem ferramentas externas"""
        self.log_verbose("Usando detecção SMB básica...")
        
        smb_info = {
            "ports_open": [],
            "smb_detected": False
        }
        
        # Verificar portas SMB/NetBIOS
        smb_ports = [139, 445]
        for port in smb_ports:
            if self.check_port(port):
                smb_info["ports_open"].append(port)
                smb_info["smb_detected"] = True
                self.log_verbose(f"SMB detectado na porta {port}")
                
        self.results["smb_info"] = smb_info
        
    def enumerate_users(self):
        """Enumeração de usuários (se possível sem autenticação)"""
        self.log_verbose("Tentando enumerar usuários...")
        
        try:
            cmd = ["rpcclient", "-U", "%", "-c", "enumdomusers", self.target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0 and "user:" in result.stdout:
                users = self.parse_rpcclient_users(result.stdout)
                self.results["users"] = users
                self.log_verbose(f"Usuários encontrados: {len(users)}")
            else:
                self.log_verbose("Enumeração de usuários não disponível")
                
        except Exception as e:
            self.log_verbose(f"Enumeração de usuários falhou: {e}")
            
    def parse_rpcclient_users(self, output):
        """Parse da saída do rpcclient para usuários"""
        users = []
        lines = output.split('\n')
        
        for line in lines:
            if "user:" in line:
                user_match = re.search(r'user:\[(.+?)\]', line)
                if user_match:
                    username = user_match.group(1)
                    rid_match = re.search(r'rid:\[(.+?)\]', line)
                    rid = rid_match.group(1) if rid_match else "Unknown"
                    
                    users.append({
                        "username": username,
                        "rid": rid
                    })
                    
        return users
        
    def check_null_session(self):
        """Verifica se sessões nulas são permitidas"""
        self.log_verbose("Verificando sessões nulas...")
        
        try:
            cmd = ["smbclient", "-L", self.target_ip, "-N"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            null_session_allowed = result.returncode == 0 and "NT_STATUS" not in result.stderr
            
            self.results["security_info"]["null_session"] = {
                "allowed": null_session_allowed,
                "tested": True
            }
            
            if null_session_allowed:
                self.log_verbose("Sessões nulas PERMITIDAS - Vulnerabilidade!")
            else:
                self.log_verbose("Sessões nulas bloqueadas")
                
        except Exception as e:
            self.log_verbose(f"Teste de sessão nula falhou: {e}")
            
    def check_smb_signing(self):
        """Verifica configuração de assinatura SMB"""
        self.log_verbose("Verificando assinatura SMB...")
        
        try:
            cmd = ["smbclient", "-L", self.target_ip, "-N", "--option=client_signing=disabled"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            signing_required = "NT_STATUS_ACCESS_DENIED" in result.stderr or result.returncode != 0
            
            self.results["security_info"]["smb_signing"] = {
                "required": signing_required,
                "tested": True
            }
            
            if not signing_required:
                self.log_verbose("Assinatura SMB NÃO obrigatória - Possível vulnerabilidade!")
            else:
                self.log_verbose("Assinatura SMB obrigatória")
                
        except Exception as e:
            self.log_verbose(f"Teste de assinatura SMB falhou: {e}")
            
    def enumerate_sessions(self):
        """Enumera sessões ativas"""
        self.log_verbose("Enumerando sessões ativas...")
        
        try:
            cmd = ["rpcclient", "-U", "%", "-c", "netshareenum", self.target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                sessions = self.parse_sessions(result.stdout)
                self.results["sessions"] = sessions
                self.log_verbose(f"Sessões encontradas: {len(sessions)}")
                
        except Exception as e:
            self.log_verbose(f"Enumeração de sessões falhou: {e}")
            
    def parse_sessions(self, output):
        """Parse de sessões ativas"""
        sessions = []
        # Parse básico - implementar conforme necessário
        if "netname:" in output:
            lines = output.split('\n')
            for line in lines:
                if "netname:" in line:
                    sessions.append({"info": line.strip()})
        return sessions
        
    def port_scan(self):
        """Scan das portas relacionadas a SMB/NetBIOS"""
        self.log_verbose("Verificando portas SMB/NetBIOS...")
        
        smb_ports = [135, 137, 138, 139, 445]
        open_ports = []
        
        for port in smb_ports:
            if self.check_port(port):
                open_ports.append({
                    "port": port,
                    "service": self.get_service_name(port),
                    "status": "open"
                })
                self.log_verbose(f"Porta {port} ABERTA")
            else:
                self.log_verbose(f"Porta {port} fechada")
                
        self.results["open_ports"] = open_ports
        
    def get_service_name(self, port):
        """Retorna nome do serviço para a porta"""
        services = {
            135: "RPC Endpoint Mapper",
            137: "NetBIOS Name Service",
            138: "NetBIOS Datagram Service", 
            139: "NetBIOS Session Service",
            445: "SMB over TCP"
        }
        return services.get(port, f"Unknown ({port})")
        
    def enumerate(self):
        """Executa enumeração completa"""
        start_time = time.time()
        
        print(f"\n{conf.PURPLE}[*] Iniciando enumeração SMB para {self.target_ip}{conf.RESET}")
        
        # Verificar conectividade básica
        if not self.check_port(445) and not self.check_port(139):
            error_msg = "Nenhuma porta SMB encontrada aberta (139, 445)"
            self.log_error(error_msg)
            self.results["duration"] = time.time() - start_time
            return self.results
            
        # Executar todas as enumerações
        steps = [
            ("Verificando portas", self.port_scan),
            ("NetBIOS query", self.netbios_name_query),
            ("Versão SMB", self.get_smb_version),
            ("Compartilhamentos", self.enumerate_smb_shares),
            ("Usuários", self.enumerate_users),
            ("Sessões nulas", self.check_null_session),
            ("Assinatura SMB", self.check_smb_signing),
            ("Sessões ativas", self.enumerate_sessions)
        ]
        
        progress = ProgressUpdater(len(steps))
        progress.start()
        
        for step_name, step_func in steps:
            try:
                print(f"\n{conf.YELLOW}[*] {step_name}...{conf.RESET}")
                step_func()
                progress.increment()
            except Exception as e:
                self.log_error(f"Erro em {step_name}: {e}")
                progress.increment()
                
        progress.stop()
        
        self.results["duration"] = time.time() - start_time
        
        # Resumo final
        self.print_summary()
        
        return self.results
        
    def print_summary(self):
        """Imprime resumo dos resultados"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} RESUMO DA ENUMERAÇÃO SMB {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.YELLOW}Alvo:{conf.RESET} {self.target_ip}")
        print(f"{conf.YELLOW}Duração:{conf.RESET} {self.results['duration']:.2f} segundos")
        
        # Portas abertas
        if self.results["open_ports"]:
            print(f"\n{conf.GREEN}Portas Abertas:{conf.RESET}")
            for port_info in self.results["open_ports"]:
                print(f"  • {port_info['port']}/tcp - {port_info['service']}")
        
        # NetBIOS
        if self.results["netbios_info"]:
            print(f"\n{conf.GREEN}NetBIOS:{conf.RESET}")
            for name, info in self.results["netbios_info"].items():
                if isinstance(info, dict):
                    print(f"  • {name} - {info.get('type', 'Unknown')}")
        
        # Compartilhamentos
        if self.results["shares"]:
            print(f"\n{conf.GREEN}Compartilhamentos:{conf.RESET}")
            for share in self.results["shares"]:
                print(f"  • {share['name']} ({share['type']}) - {share['comment']}")
        
        # Informações SMB
        if self.results["smb_info"]:
            print(f"\n{conf.GREEN}Informações SMB:{conf.RESET}")
            smb_info = self.results["smb_info"]
            if "os_version" in smb_info and smb_info["os_version"]:
                print(f"  • OS: {smb_info['os_version']}")
            if "smb_version" in smb_info and smb_info["smb_version"]:
                print(f"  • Versão: {smb_info['smb_version']}")
            if "domain" in smb_info and smb_info["domain"]:
                print(f"  • Domínio: {smb_info['domain']}")
        
        # Vulnerabilidades
        vulnerabilities = []
        if self.results.get("security_info", {}).get("null_session", {}).get("allowed"):
            vulnerabilities.append("Sessões nulas permitidas")
        if not self.results.get("security_info", {}).get("smb_signing", {}).get("required"):
            vulnerabilities.append("Assinatura SMB não obrigatória")
            
        if vulnerabilities:
            print(f"\n{conf.RED}Possíveis Vulnerabilidades:{conf.RESET}")
            for vuln in vulnerabilities:
                print(f"  ⚠ {vuln}")
        
        # Erros
        if self.results["errors"]:
            print(f"\n{conf.RED}Erros Encontrados:{conf.RESET}")
            for error in self.results["errors"][-3:]:  # Últimos 3 erros
                print(f"  • {error}")
                
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")