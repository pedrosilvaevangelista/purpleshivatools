#!/usr/bin/env python3
# Port scanner

import socket
import concurrent.futures
import os
import xml.etree.ElementTree as ET
from datetime import datetime
 
# Configurações do sistema de logs
LOG_DIR = "/var/log/port_scanner"  # Diretório padrão para logs (requer sudo)
FILENAME_PREFIX = "openports"      # Prefixo dos arquivos de log
 
def scan_port(target, port):
    """Escaneia uma porta individual e retorna informações se estiver aberta."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = get_service_name(port)
                vuln_info = get_vulnerability_info(port)
                return (port, service, vuln_info)
        return None
    except Exception as e:
        print(f"[ERRO] Ao escanear porta {port}: {str(e)}")
        return None
 
def scan_ports(target):
    """Escaneia todas as portas (1-65535) com paralelismo."""
    print(f"\n[+] Iniciando varredura em {target}...")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in range(1, 65536)}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"[+] Porta {result[0]}/{result[1]} aberta")
                if result[2]:
                    print(f"    [!] Vulnerabilidades: {result[2]}\n")
 
    print(f"\n[+] Varredura concluída! {len(open_ports)} portas abertas encontradas.")
    return open_ports
 
def save_to_xml(target, open_ports):
    """Salva os resultados em um arquivo XML estruturado."""
    try:
        # Criar diretório se não existir
        os.makedirs(LOG_DIR, exist_ok=True)
        # Gerar nome do arquivo
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{FILENAME_PREFIX}_{target}_{timestamp}.xml"
        filepath = os.path.join(LOG_DIR, filename)
        # Criar estrutura XML
        root = ET.Element("PortScannerReport")
        ET.SubElement(root, "Target").text = target
        ET.SubElement(root, "ScanDate").text = datetime.now().isoformat()
        ET.SubElement(root, "TotalOpenPorts").text = str(len(open_ports))
        ports_element = ET.SubElement(root, "OpenPorts")
        for port, service, vuln in open_ports:
            port_element = ET.SubElement(ports_element, "Port")
            ET.SubElement(port_element, "Number").text = str(port)
            ET.SubElement(port_element, "Service").text = service
            ET.SubElement(port_element, "Vulnerabilities").text = vuln if vuln else "Nenhuma conhecida"
        # Formatar e salvar XML
        ET.indent(root, space="  ")  # Melhorar legibilidade
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        print(f"\n[+] Log salvo em: {filepath}")
        return filepath
    except Exception as e:
        print(f"[ERRO] Ao gerar log XML: {str(e)}")
        return None
 
def get_service_name(port):
    """Mapeia números de porta para nomes de serviços."""
    service_map = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 1433: "MS-SQL", 1521: "Oracle", 2049: "NFS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        5353: "mDNS", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached"
    }
    return service_map.get(port, "Unknown")
 
def get_vulnerability_info(port):
    """Retorna informações de vulnerabilidades conhecidas por porta."""
    vuln_db = {
        21: "Anonymous login, Brute Force, Exploits de versões antigas",
        22: "Brute Force SSH, Shellshock, Chaves fracas",
        23: "Credenciais padrão, Comunicação não criptografada",
        80: "SQL Injection, XSS, Directory Traversal",
        443: "Heartbleed, POODLE, Certificados inválidos",
        445: "EternalBlue, SMB Exploits, Ransomware",
        3389: "BlueKeep, Credential Theft",
        5900: "Autenticação fraca, VNC exploits"
    }
    return vuln_db.get(port, None)
 
if __name__ == "__main__":
    try:
        # Configuração
        target = input("[?] Digite o IP/Domínio para escanear: ").strip()
        # Executar varredura
        results = scan_ports(target)
        # Gerar log
        if results:
            save_to_xml(target, results)
        else:
            print("[!] Nenhuma porta aberta encontrada.")
    except KeyboardInterrupt:
        print("\n[!] Varredura interrompida pelo usuário.")
    except Exception as e:
        print(f"[ERRO CRÍTICO] {str(e)}")