#!/usr/bin/env python3
# SMB Enumeration + Reporting

import subprocess
import socket
import xml.etree.ElementTree as ET
import re

def is_smb_open(ip):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, 445))
        sock.close()
        return True
    except:
        return False

def run_enum4linux(ip):
    try:
        result = subprocess.check_output(["enum4linux", "-a", ip], stderr=subprocess.DEVNULL)
        return result.decode(errors="ignore")
    except Exception as e:
        return f"Erro ao executar enum4linux: {e}"

def run_smbclient(ip):
    try:
        result = subprocess.check_output(["smbclient", "-L", f"//{ip}/", "-N"], stderr=subprocess.DEVNULL)
        return result.decode(errors="ignore")
    except Exception as e:
        return f"Erro ao executar smbclient: {e}"

def parse_enum4linux(output):
    parsed = {
        "dominio": "",
        "usuarios": [],
        "shares": [],
        "versao": "",
        "politicas": []
    }

    for line in output.splitlines():
        line = line.strip()
        if "Workgroup" in line or "Domain Name:" in line:
            parsed["dominio"] = line.split(":")[-1].strip()
        elif re.match(r"^\s*\[\+\]\s+[a-zA-Z0-9_-]+$", line):
            user = line.split()[-1]
            if user.lower() not in parsed["usuarios"]:
                parsed["usuarios"].append(user)
        elif re.search(r"(Disk|IPC)", line) and ("READ" in line or "NO ACCESS" in line):
            parsed["shares"].append(line)
        elif "Samba" in line:
            parsed["versao"] = line
        elif "Minimum password length" in line or "Password history" in line or "Complexity" in line:
            parsed["politicas"].append(line)

    return parsed

def print_output(ip, parsed, raw_enum, raw_smb, output_type):
    print(f"\n📍 Resultado para {ip}\n")
    
    if output_type == "light":
        print("🔐 Domínio / Workgroup:")
        print(f"  {parsed['dominio'] or 'Não identificado'}")

        print("\n👤 Usuários encontrados:")
        for user in parsed['usuarios']:
            print(f"  - {user}")
        if not parsed['usuarios']:
            print("  Nenhum usuário listado.")
        
        print("\n📂 Compartilhamentos (shares):")
        for share in parsed['shares']:
            print(f"  - {share}")
        if not parsed['shares']:
            print("  Nenhum compartilhamento detectado.")
        
        print("\n🛠 Versão do Samba/SMB:")
        print(f"  {parsed['versao'] or 'Não detectada'}")
        
        print("\n🔐 Políticas de senha:")
        for policy in parsed['politicas']:
            print(f"  - {policy}")
        if not parsed['politicas']:
            print("  Nenhuma política visível.")
    else:
        print("🔐 Domínio / Workgroup:")
        print(f"  {parsed['dominio'] or 'Não identificado'}")

        print("\n👤 Usuários encontrados:")
        for user in parsed['usuarios']:
            print(f"  - {user}")
        if not parsed['usuarios']:
            print("  Nenhum usuário listado.")

        print("\n📂 Compartilhamentos (shares):")
        for share in parsed['shares']:
            print(f"  - {share}")
        if not parsed['shares']:
            print("  Nenhum compartilhamento detectado.")

        print("\n🛠 Versão do Samba/SMB:")
        print(f"  {parsed['versao'] or 'Não detectada'}")

        print("\n🔐 Políticas de senha:")
        for policy in parsed['politicas']:
            print(f"  - {policy}")
        if not parsed['politicas']:
            print("  Nenhuma política visível.")

        print("\n======================")
        print("📄 SAÍDA BRUTA (enum4linux + smbclient):\n")
        print(raw_enum)
        print(raw_smb)

def gerar_xml(ip, raw_enum, raw_smb, filename="smb_enum.xml"):
    root = ET.Element("host", ip=ip)
    smb_elem = ET.SubElement(root, "smb")

    enum_elem = ET.SubElement(smb_elem, "enum4linux")
    enum_elem.text = raw_enum

    smbclient_elem = ET.SubElement(smb_elem, "smbclient")
    smbclient_elem.text = raw_smb

    tree = ET.ElementTree(root)
    tree.write(filename, encoding="utf-8", xml_declaration=True)
    print(f"[+] Resultado exportado para {filename}")

def main():
    ip = input("Digite o IP alvo: ").strip()

    output_type = input("Escolha o tipo de saída (light/full): ").strip().lower()
    if output_type not in ["light", "full"]:
        print("Opção inválida. Usando 'light' como padrão.")
        output_type = "light"

    if not is_smb_open(ip):
        print(f"[-] A porta 445 não está aberta em {ip}.")
        return

    print(f"[+] Porta 445 aberta em {ip}, iniciando enumeração...\n")

    raw_enum = run_enum4linux(ip)
    raw_smb = run_smbclient(ip)

    parsed = parse_enum4linux(raw_enum)
    print_output(ip, parsed, raw_enum, raw_smb, output_type)

    exportar = input("\nDeseja exportar para XML? (s/n): ").strip().lower()
    if exportar == "s":
        gerar_xml(ip, raw_enum, raw_smb)

if __name__ == "__main__":
    main()
