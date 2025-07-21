# NMAP Vulners Services Scan

import subprocess
import re
import xml.etree.ElementTree as ET
import time
from datetime import datetime
import json
from .progress import ProgressUpdater
from modules import config as conf

class VulnerabilityScanner:
    def __init__(self, target, ports, scan_type="tcp", timing=3):
        self.target = target
        self.ports = ports
        self.scan_type = scan_type.lower()
        self.timing = timing
        self.start_time = None
        self.end_time = None
        
    def _validate_target(self):
        """Validates if the target is a valid IP"""
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, self.target):
            raise ValueError(f"Invalid IP: {self.target}")
    
    def _validate_ports(self):
        """Validates port format"""
        if '-' in self.ports:
            try:
                start, end = map(int, self.ports.split('-'))
                if start > end or start < 1 or end > 65535:
                    raise ValueError("Invalid port range")
            except ValueError:
                raise ValueError(f"Invalid port format: {self.ports}")
        else:
            try:
                port = int(self.ports)
                if port < 1 or port > 65535:
                    raise ValueError("Port out of valid range")
            except ValueError:
                raise ValueError(f"Invalid port: {self.ports}")
    
    def _build_nmap_command(self):
        """Builds the nmap command with vulners script"""
        cmd = ["nmap"]
        
        # Add scan options
        if self.scan_type == "tcp":
            cmd.append("-sS")
        elif self.scan_type == "udp":
            cmd.append("-sU")
        elif self.scan_type == "both":
            cmd.extend(["-sS", "-sU"])
        
        # Timing template
        cmd.append(f"-T{self.timing}")
        
        # Vulnerability detection scripts
        cmd.extend([
            "--script", "vulners,/usr/share/nmap/scripts/vulscan",
            "-sV",
            "--version-intensity", "5"
        ])
        
        # XML output format
        cmd.extend(["-oX", "-"])
        
        # Ports and target
        cmd.extend(["-p", self.ports, self.target])
        
        return cmd
    
    def _parse_nmap_xml(self, xml_output):
        """Parses nmap XML to extract information"""
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            raise ValueError(f"XML parse error: {e}")
        
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
        
        for host in root.findall(".//host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            
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
                    
                    for script in port.findall(".//script"):
                        script_id = script.get("id")
                        if script_id in ["vulners", "vulscan"]:
                            vulns = self._parse_vulnerability_script(script, port_num, service_info.get("name", "unknown"))
                            results["vulnerabilities"].extend(vulns)
        
        if self.start_time and self.end_time:
            results["duration"] = self.end_time - self.start_time
            
        return results
    
    def _parse_vulnerability_script(self, script_elem, port, service_name):
        """Parses vulnerabilities found by scripts"""
        vulnerabilities = []
        script_output = script_elem.get("output", "")
        
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cvss_pattern = r'(\d+\.\d+)'
        
        cves = re.findall(cve_pattern, script_output)
        
        for cve in cves:
            cve_context = script_output[script_output.find(cve):script_output.find(cve)+200]
            cvss_scores = re.findall(cvss_pattern, cve_context)
            
            score = float(cvss_scores[0]) if cvss_scores else 0.0
            
            if score >= 9.0:
                severity = "critical"
            elif score >= 7.0:
                severity = "high"
            elif score >= 4.0:
                severity = "medium"
            else:
                severity = "low"
            
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
        """Executes the nmap scan"""
        cmd = self._build_nmap_command()
        
        print(f"\n{conf.YELLOW}[*] Running command: {' '.join(cmd)}{conf.RESET}")
        print(f"{conf.YELLOW}[*] Please wait, this may take a few minutes...{conf.RESET}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                raise RuntimeError(f"Nmap failed: {error_msg}")
            
            return result.stdout
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Scan timeout - operation canceled after 30 minutes")
        except FileNotFoundError:
            raise RuntimeError("Nmap not found. Install with: sudo apt install nmap")
        except Exception as e:
            raise RuntimeError(f"Error running nmap: {e}")
    
    def scan(self):
        """Runs the full scan"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} STARTING VULNERABILITY SCAN {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        try:
            self._validate_target()
            self._validate_ports()
        except ValueError as e:
            print(f"{conf.RED}[!] Validation error: {e}{conf.RESET}")
            raise
        
        print(f"{conf.GREEN}[✓] Target validated: {self.target}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Ports validated: {self.ports}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Scan type: {self.scan_type.upper()}{conf.RESET}")
        print(f"{conf.GREEN}[✓] Timing template: T{self.timing}{conf.RESET}")
        
        progress = ProgressUpdater(task_type="vulnerability scan")
        progress.start()
        
        try:
            self.start_time = time.time()
            
            xml_output = self._run_nmap_scan()
            
            self.end_time = time.time()
            progress.stop()
            
            print(f"\n{conf.YELLOW}[*] Processing results...{conf.RESET}")
            results = self._parse_nmap_xml(xml_output)
            
            self._print_summary(results)
            
            return results
            
        except Exception as e:
            progress.stop()
            print(f"\n{conf.RED}[!] Scan error: {e}{conf.RESET}")
            raise
    
    def _print_summary(self, results):
        """Displays scan summary"""
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} SCAN SUMMARY {conf.RESET}")
        print(f"{conf.PURPLE}{'='*60}{conf.RESET}")
        
        print(f"\n{conf.BOLD}Target:{conf.RESET} {results['target']}")
        print(f"{conf.BOLD}Duration:{conf.RESET} {results['duration']:.2f} seconds")
        print(f"{conf.BOLD}Open ports:{conf.RESET} {len(results['open_ports'])}")
        print(f"{conf.BOLD}Identified services:{conf.RESET} {len(results['services'])}")
        print(f"{conf.BOLD}Discovered vulnerabilities:{conf.RESET} {len(results['vulnerabilities'])}")
        
        if results['vulnerabilities']:
            critical = len([v for v in results['vulnerabilities'] if v['severity'] == 'critical'])
            high = len([v for v in results['vulnerabilities'] if v['severity'] == 'high'])
            medium = len([v for v in results['vulnerabilities'] if v['severity'] == 'medium'])
            low = len([v for v in results['vulnerabilities'] if v['severity'] == 'low'])
            
            print(f"\n{conf.BOLD}Vulnerability severity:{conf.RESET}")
            if critical > 0:
                print(f"  {conf.RED}Critical: {critical}{conf.RESET}")
            if high > 0:
                print(f"  {conf.YELLOW}High: {high}{conf.RESET}")
            if medium > 0:
                print(f"  {conf.BLUE}Medium: {medium}{conf.RESET}")
            if low > 0:
                print(f"  {conf.GREEN}Low: {low}{conf.RESET}")
            
            # Display top 5 vulnerabilities (sorted by severity score)
            print(f"\n{conf.BOLD}Top vulnerabilities found:{conf.RESET}")
            
            # Deduplicate vulnerabilities by CVE and port combination
            unique_vulns = {}
            for vuln in results['vulnerabilities']:
                key = f"{vuln['cve']}_{vuln['port']}"
                if key not in unique_vulns or vuln['score'] > unique_vulns[key]['score']:
                    unique_vulns[key] = vuln
            
            sorted_vulns = sorted(unique_vulns.values(), key=lambda x: x['score'], reverse=True)
            
            for i, vuln in enumerate(sorted_vulns[:5]):
                severity_color = {
                    'critical': conf.RED,
                    'high': conf.YELLOW,
                    'medium': conf.BLUE,
                    'low': conf.GREEN
                }.get(vuln['severity'], conf.RESET)
                
                print(f"  {i+1}. {vuln['cve']} - {severity_color}{vuln['severity'].upper()}{conf.RESET} "
                    f"(Score: {vuln['score']}) - Port {vuln['port']}/{vuln['service']}")
                if vuln['description']:
                    print(f"     {vuln['description'][:80]}{'...' if len(vuln['description']) > 80 else ''}")
            
            if len(unique_vulns) > 5:
                remaining = len(unique_vulns) - 5
                print(f"\n{conf.CYAN}[*] {remaining} additional vulnerabilities found.{conf.RESET}")
                print(f"{conf.CYAN}[*] For complete details, please check the full report.{conf.RESET}")
            
            print(f"\n{conf.RED}[!] WARNING: Critical/high vulnerabilities found!{conf.RESET}")
            print(f"{conf.YELLOW}[*] Check the report for details and recommendations{conf.RESET}")

        if results['open_ports']:
            print(f"\n{conf.BOLD}Open ports:{conf.RESET}")
            for port_info in results['open_ports'][:10]:
                print(f"  {port_info['port']}/{port_info['protocol']} - {port_info['state']}")
            if len(results['open_ports']) > 10:
                print(f"  ... and {len(results['open_ports']) - 10} more ports")
        
        print(f"\n{conf.PURPLE}{'='*60}{conf.RESET}")
