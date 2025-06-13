# NMAP Vulners Services

import subprocess
import re
import xml.etree.ElementTree as ET
import time
from datetime import datetime
import json
from .progress import ProgressUpdater
import config as conf

class VulnerabilityScanner:
    def __init__(self, target, ports, scan_type="tcp", timing=3):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type.lower()
        self.timing = timing
        self.start_time = None
        self.end_time = None
        
    def _validate_target(self):
        """Valida se o target é um IP válido"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, self.target):
            raise ValueError(f"IP inválido: {self.target}")
    
    def _validate_ports(self):
        """Valida formato das portas"""
        if '-' in self.ports:
            try:
                start, end = map(int, self.ports.split('-'))
                if start > end or start < 1 or end > 65535:
                    raise ValueError("Intervalo de portas inválido")
            except ValueError:
                raise ValueError(f"Formato de portas inválido: {self.ports}")
        else:
            try:
                port = int(self.ports)
                if port < 1 or port > 65535:
                    raise ValueError("Porta fora do intervalo válido")
            except ValueError:
                raise ValueError(f"Porta inválida: {self.ports}")
    
    def _build_nmap_command(self):
        """Constrói o comando nmap com vulners script"""
        cmd = ["nmap"]
        
        # Adicionar opções de scan
        if self.scan_type == "tcp":
            cmd.append("-sS")
        elif self.scan_type == "udp":
            cmd.append("-sU")
        elif self.scan_type == "both":
            cmd.extend(["-sS", "-sU"])
        
        # Template de timing
        cmd.append(f"-T{self.timing}")
        
        # Scripts de detecção de vulnerabilidades
        cmd.extend([
            "--script", "vulners,vulscan/",
            "-sV",  # Detecção de versão
            "--version-intensity", "5"
        ])
        
        # Formato de saída XML
        cmd.extend(["-oX", "-"])
        
        # Portas e target
        cmd.extend(["-p", self.ports, self.target])
        
        return cmd
    
    def _parse_nmap_xml(self, xml_output):
        """Parse do XML do nmap para extrair informações"""
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            raise ValueError(f"Erro ao fazer parse do XML: {e}")
        
        results = {
            "target": self.target,
            "ports_scanned": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "scan_type": self.scan_type,
            "timing": self.timing,
            "duration": 0,
            "scan_date": datetime.now().isoformat()
        }
        
        # Extrair informações dos hosts
        for host in root.findall(".//host"):
            # Verificar se host está up
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            
            # Extrair portas
            for port in host.findall(".//port"):
                port_num = int(port.get("portid"))
                protocol = port.get("protocol")
                
                state_elem = port.find("state")
                if state_elem is None:
                    continue
                    
                state = state_elem.get("state")
                results["ports_scanned"].append(port_num)
                
                if state == "open":
                    port_info = {
                        "port": port_num,
                        "protocol": protocol,
                        "state": state
                    }
                    results["open_ports"].append(port_info)
                    
                    # Extrair informações do serviço
                    service = port.find("service")
                    if service is not None:
                        service_info = {
                            "port": port_num,
                            "name": service.get("name", "unknown"),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", "")
                        }
                        results["services"].append(service_info)
                    
                    # Extrair vulnerabilidades dos scripts
                    for script in port.findall(".//script"):
                        script_id = script.get("id")
                        if script_id in ["vulners", "vulscan"]:
                            vulns = self._parse_vulnerability_script(script, port_num, service_info.get("name", "unknown"))
                            results["vulnerabilities"].extend(vulns)
        
        # Calcular duração
        if self.start_time and self.end_time:
            results["duration"] = self.end_time - self.start_time
            
        return results
    
    def _parse_vulnerability_script(self, script_elem, port, service_name):
        """Parse das vulnerabilidades encontradas pelos scripts"""
        vulnerabilities = []
        script_output = script_elem.get("output", "")
        
        # Regex para CVEs
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cvss_pattern = r'(\d+\.\d+)'
        
        # Procurar por CVEs no output
        cves = re.findall(cve_pattern, script_output)
        
        for cve in cves:
            # Tentar extrair score CVSS próximo ao CVE
            cve_context = script_output[script_output.find(cve):script_output.find(cve)+200]
            cvss_scores = re.findall(cvss_pattern, cve_context)
            
            score = float(cvss_scores[0]) if cvss_scores else 0.0
            
            # Determinar severidade baseada no score
            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
            
            # Extrair descrição básica
            description_lines = script_output.split('\n')
            description = ""
            for line in description_lines:
                if cve in line:
                    description = line.strip()
                    break
            
            vuln = {
                "cve": cve,
                "severity": severity,
                "score": score,
                "description": description,
                "port": port,
                "service": service_name
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _run_nmap_scan(self):
        """Executa o scan nmap"""
        cmd = self._build_nmap_command()
        
        print(f"\n{conf.YELLOW}[*] Executando comando: {' '.join(cmd)}{conf.RESET}")
        print(f"{conf.YELLOW}[*] Aguarde, isso pode demorar alguns minutos...{conf.RESET}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutos timeout
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Erro desconhecido"
                raise RuntimeError(f"Nmap falhou: {error_msg}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Scan timeout - operação cancelada após 30 minutos")
        except FileNotFoundError:
            raise RuntimeError("Nmap não encontrado. Instale com: sudo apt install nmap")
        except Exception as e:
            raise RuntimeError(f"Erro ao executar nmap: {e}")
    
    def scan(self):
        """Executa o scan completo"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} INICIANDO VULNERABILITY SCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        # Validações
        try:
            self._validate_target()
            self._validate_ports()
        except ValueError as e:
            print(f"{conf.RED}[!] Erro de validação: {e}{conf.RESET}")
            raise
        
        print(f"{conf.GREEN}[✓] Target validado: {self.target}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Portas validadas: {self.ports}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Tipo de scan: {self.scan_type.upper()}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Timing template: T{self.timing}{conf.RESET}")
        
        # Iniciar progresso
        progress = ProgressUpdater(task_type="vulnerability scan")
        progress.start()
        
        try:
            self.start_time = time.time()
            
            # Executar scan
            xml_output = self._run_nmap_scan()
            
            self.end_time = time.time()
            progress.stop()
            
            # Parse dos resultados
            print(f"\n{conf.YELLOW}[*] Processando resultados...{conf.RESET}")
            results = self._parse_nmap_xml(xml_output)
            
            # Exibir sumário
            self._print_summary(results)
            
            return results
            
        except Exception as e:
            progress.stop()
            print(f"\n{conf.RED}[!] Erro durante o scan: {e}{conf.RESET}")
            raise
    
    def _print_summary(self, results):
        """Exibe sumário dos resultados"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} RESUMO DO SCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.BOLD}Target:{conf.RESET} {results['target']}")
        print(f"{conf.BOLD}Duração:{conf.RESET} {results['duration']:.2f} segundos")
        print(f"{conf.BOLD}Portas abertas:{conf.RESET} {len(results['open_ports'])}")
        print(f"{conf.BOLD}Serviços identificados:{conf.RESET} {len(results['services'])}")
        print(f"{conf.BOLD}Vulnerabilidades encontradas:{conf.RESET} {len(results['vulnerabilities'])}")
        
        if results['vulnerabilities']:
            critical = len([v for v in results['vulnerabilities'] if v['severity'] == 'critical'])
            high = len([v for v in results['vulnerabilities'] if v['severity'] == 'high'])
            medium = len([v for v in results['vulnerabilities'] if v['severity'] == 'medium'])
            low = len([v for v in results['vulnerabilities'] if v['severity'] == 'low'])
            
            print(f"\n{conf.BOLD}Severidade das vulnerabilidades:{conf.RESET}")
            if critical > 0:
                print(f"  {conf.RED}Críticas: {critical}{conf.RESET}")
            if high > 0:
                print(f"  {conf.YELLOW}Altas: {high}{conf.RESET}")
            if medium > 0:
                print(f"  {conf.BLUE}Médias: {medium}{conf.RESET}")
            if low > 0:
                print(f"  {conf.GREEN}Baixas: {low}{conf.RESET}")
            
            print(f"\n{conf.RED}[!] ATENÇÃO: Vulnerabilidades críticas/altas encontradas!{conf.RESET}")
            print(f"{conf.YELLOW}[*] Consulte o relatório para detalhes e recomendações{conf.RESET}")
        
        if results['open_ports']:
            print(f"\n{conf.BOLD}Portas abertas:{conf.RESET}")
            for port_info in results['open_ports'][:10]:  # Mostrar até 10 portas
                print(f"  {port_info['port']}/{port_info['protocol']} - {port_info['state']}")
            if len(results['open_ports']) > 10:
                print(f"  ... e mais {len(results['open_ports']) - 10} portas")
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")