#!/usr/bin/env python3
# Nmap Vulnerable services detection

import subprocess
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

def construir_comando(ip_alvo, porta=None):
    comando = ["nmap", "-sV", "--script", "vulners"]
    if porta:
        comando += ["-p", str(porta)]
    comando += ip_alvo.split()
    return comando

def executar_nmap(comando):
    try:
        resultado = subprocess.run(
            comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if resultado.stderr:
            print(Fore.RED + "[!] Erro durante execução do Nmap:")
            print(resultado.stderr)
            return None
        return resultado.stdout
    except FileNotFoundError:
        print(Fore.RED + "[!] Nmap não está instalado ou não está no PATH.")
        return None

def extrair_cves(saida):
    cves_detectadas = {}
    servico_atual = None
    ip_atual = ""

    for linha in saida.splitlines():
        if re.match(r"Nmap scan report for ", linha):
            ip_atual = linha.split()[-1]

        elif re.match(r"^\d+/tcp\s+open\s+", linha):
            servico_atual = linha
            print(Fore.CYAN + f"\n[PORTA/SERVIÇO] {servico_atual}")

        elif "| vulners:" in linha:
            print(Fore.YELLOW + "  [*] Verificando CVEs via vulners.nse...")

        elif "CVE-" in linha:
            cve_match = re.findall(r"CVE-\d{4}-\d{4,7}", linha)
            for cve in cve_match:
                chave = (ip_atual, servico_atual)
                cves_detectadas.setdefault(chave, set()).add(cve)
                print(Fore.GREEN + f"  [+] Vulnerabilidade encontrada: {cve}")
    return cves_detectadas

def exportar_para_xml(cves_dict, nome_arquivo):
    root = ET.Element("RelatorioVulnerabilidades")
    for (ip, servico), cves in cves_dict.items():
        host_elem = ET.SubElement(root, "Host", ip=ip)
        servico_elem = ET.SubElement(host_elem, "Servico", descricao=servico)
        for cve in sorted(cves):
            ET.SubElement(servico_elem, "CVE").text = cve

    tree = ET.ElementTree(root)
    tree.write(nome_arquivo, encoding="utf-8", xml_declaration=True)
    print(Fore.BLUE + f"\n[+] CVEs exportados para '{nome_arquivo}' com sucesso.")

def escanear_vulners(lista_ips, porta=None):
    comando = construir_comando(lista_ips, porta)
    print(Fore.MAGENTA + f"[+] Escaneando: {lista_ips}")
    saida = executar_nmap(comando)

    if saida:
        print(Fore.MAGENTA + "[+] Analisando resultados...\n")
        cves = extrair_cves(saida)
        if not cves:
            print(Fore.YELLOW + "[-] Nenhuma vulnerabilidade encontrada.")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            nome_arquivo = f"relatorio_cves_{timestamp}.xml"
            exportar_para_xml(cves, nome_arquivo)
    else:
        print(Fore.RED + "[-] Falha ao obter resultados do Nmap.")

if __name__ == "__main__":
    print(Style.BRIGHT + Fore.CYAN + "=== Escaneador de Vulnerabilidades com Nmap ===\n")
    ips = input("Digite o(s) IP(s) ou faixa(s) de IPs (ex: 192.168.0.1 ou 192.168.0.0/24): ").strip()
    porta = input("Digite a porta (pressione Enter para escanear todas): ").strip()
    porta = porta if porta else None
    escanear_vulners(ips, porta)
