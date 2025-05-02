#!/usr/bin/env python3
# Port Scanner Tool with Enhanced Reporting and Security Recommendations

import socket
import concurrent.futures
import sys
import time
import threading
import signal
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Security recommendations specific to port scanning
RECOMMENDATIONS = [
    {"id": 1, "title": "Patch Management", "severity": "High",
     "description": "Ensure all discovered services are up-to-date with the latest security patches to mitigate known vulnerabilities.",
     "metrics": {"patched_services": "percentage of services patched", "vulnerability_age": "average days since last patch"},
     "sources": ["CVE Database: Patch release notes", "NIST: Patch management best practices"]},
    {"id": 2, "title": "Firewall Configuration", "severity": "Medium",
     "description": "Use host-based or network firewalls to limit exposure of sensitive ports to trusted hosts only.",
     "metrics": {"filtered_ports": "number of ports filtered", "allowed_hosts": "count of whitelisted hosts"},
     "sources": ["iptables: firewall configuration guide", "Palo Alto Networks: firewall best practices"]},
    {"id": 3, "title": "Service Hardening", "severity": "Medium",
     "description": "Disable or remove unnecessary services and apply secure configurations (e.g., disable telnet, enforce SSH key-based auth).",
     "metrics": {"disabled_services": "count of unused services disabled", "compliance_score": "percentage of services hardened"},
     "sources": ["CIS Benchmarks: Service hardening", "Microsoft: Windows service security"]},
    {"id": 4, "title": "Network Segmentation", "severity": "Low",
     "description": "Segment production, development, and management networks to reduce blast radius of compromised hosts.",
     "metrics": {"segments_deployed": "number of network segments", "exposed_services": "number of services across segments"},
     "sources": ["NIST SP 800-125: Network isolation guidelines", "Academic study: VLAN segmentation effectiveness"]}
]

# Directory for logs
LOG_DIR = os.path.expanduser("/var/log/purpleshivatoolslog")
os.makedirs(LOG_DIR, exist_ok=True)

# Timer control\stopTimer = False
progressLine = ""
stdoutLock = threading.Lock()
timerThread = None

totalPorts = 65535
open_ports = []

# Optional root check
if os.geteuid() != 0:
    print(f"{RED}Warning: Run as root for most accurate port detection.{RESET}")

# Timer thread
def update_timer(start_time):
    global stopTimer
    while not stopTimer:
        elapsed = time.time() - start_time
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsed_str}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

# Scan a single port
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((target, port)) == 0:
                service = get_service_name(port)
                return (port, service)
    except:
        pass
    return None

# Perform port scan
def scan_ports(target):
    global stopTimer, progressLine, timerThread, open_ports
    print(f"\n{RED}Initializing port scan on target:{RESET} {BOLD}{target}{RESET}")
    open_ports.clear()
    start_time = time.time()
    progressLine = f"Progress: {BOLD}0.00%{RESET} | Port: {BOLD}---{RESET} | Open: {BOLD}0{RESET}"

    stopTimer = False
    timerThread = threading.Thread(target=update_timer, args=(start_time,))
    timerThread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in range(1, totalPorts + 1)}
        for count, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            res = future.result()
            if res:
                open_ports.append(res)
            progress = (count / totalPorts) * 100
            current = res[0] if res else futures[future]
            progressLine = (
                f"Progress: {BOLD}{progress:.2f}%{RESET} | Port: {BOLD}{current}{RESET} | Open: {BOLD}{len(open_ports)}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    stopTimer = True
    timerThread.join()
    print()
    return open_ports

# Display results
def print_open_ports(ports):
    print("\nOpen ports found:")
    print("Port\tService")
    print("-------------------------")
    for port, svc in sorted(ports, key=lambda x: x[0]):
        print(f"{port}\t{svc}")

# XML log
def write_xml_log(filepath, target, ports):
    root = ET.Element("PortScanLog")
    ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
    ET.SubElement(root, "Target").text = target
    ET.SubElement(root, "TotalOpenPorts").text = str(len(ports))

    ports_el = ET.SubElement(root, "OpenPorts")
    for port, svc in ports:
        p = ET.SubElement(ports_el, "PortEntry")
        ET.SubElement(p, "Port").text = str(port)
        ET.SubElement(p, "Service").text = svc

    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        r = ET.SubElement(recs, "Recommendation")
        ET.SubElement(r, "ID").text = str(rec["id"])
        ET.SubElement(r, "Title").text = rec["title"]
        ET.SubElement(r, "Severity").text = rec["severity"]
        ET.SubElement(r, "Description").text = rec["description"]

    tree = ET.ElementTree(root)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    print(f"\n{BOLD}XML log written to:{RESET} {filepath}")

# JSON log
def write_json_log(filepath, target, ports):
    data = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "total_open_ports": len(ports),
        "open_ports": [{"port": p, "service": s} for p, s in ports],
        "security_recommendations": RECOMMENDATIONS
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"\n{BOLD}JSON log written to:{RESET} {filepath}")

# PDF report
def write_pdf_log(filepath, target, ports):
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []

    elems.append(Paragraph("Port Scan Report", styles['Title']))
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(f"Target: {target}", styles['Normal']))
    elems.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elems.append(Paragraph(f"Total Open Ports: {len(ports)}", styles['Normal']))
    elems.append(Spacer(1, 12))

    elems.append(Paragraph("Discovered Open Ports", styles['Heading2']))
    table_data = [['Port', 'Service']]
    for p, s in ports:
        table_data.append([str(p), s])

    table = Table(table_data, colWidths=[100, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5'))
    ]))
    elems.append(table)
    elems.append(Spacer(1, 20))

    elems.append(Paragraph("Security Recommendations", styles['Heading2']))
    for rec in RECOMMENDATIONS:
        elems.append(Paragraph(f"<b>{rec['title']} (Severity: {rec['severity']})</b>", styles['BodyText']))
        elems.append(Paragraph(rec['description'], styles['BodyText']))
        metrics = "<br/>".join([f"- {k}: {v}" for k, v in rec['metrics'].items()])
        elems.append(Paragraph(f"<i>Metrics:</i><br/>{metrics}", styles['BodyText']))
        sources = "<br/>".join([f"- {s}" for s in rec['sources']])
        elems.append(Paragraph(f"<i>Sources:</i><br/>{sources}", styles['BodyText']))
        elems.append(Spacer(1, 12))

    doc.build(elems)
    print(f"\n{BOLD}PDF log written to:{RESET} {filepath}")

# Helper: extensive service mapping
def get_service_name(port):
    # Extensive service mapping
    mapping = {
        1: "TCMPMUX", 7: "Echo", 9: "Discard", 11: "System Status", 13: "Daytime",
        17: "Quote of the Day", 19: "Chargen", 20: "FTP-Data", 21: "FTP", 22: "SSH",
        23: "Telnet", 25: "SMTP", 37: "Time", 39: "RLP", 42: "Host Name",
        43: "WhoIs", 49: "TACACS", 53: "DNS", 67: "DHCP", 68: "DHCP-Client",
        69: "TFTP", 70: "Gopher", 79: "Finger", 80: "HTTP", 88: "Kerberos",
        101: "Host-based Entry", 102: "ISO-TSAP", 110: "POP3", 111: "RPCbind",
        113: "Ident", 119: "NNTP", 123: "NTP", 135: "MS-RPC",
        137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
        161: "SNMP", 162: "SNMPTRAP", 179: "BGP", 389: "LDAP",
        443: "HTTPS", 445: "SMB", 464: "Kerberos Change/Set",
        465: "SMTPS", 514: "Syslog", 515: "Line Printer Daemon",
        520: "RIP", 543: "Kerberos Master", 544: "Kerberos Slave",
        548: "AFP", 554: "RTSP", 587: "SMTP-Submission", 631: "IPP",
        636: "LDAPS", 691: "MSFTPSVC", 989: "FTPS-Data", 990: "FTPS",
        993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
        1433: "MS-SQL", 1434: "MS-SQL Monitor", 1521: "Oracle",
        1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL",
        2181: "Zookeeper", 3306: "MySQL", 3389: "RDP",
        3690: "Subversion", 5432: "PostgreSQL", 5900: "VNC",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
        6667: "IRC", 6881: "BitTorrent", 8000: "Alternate HTTP",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "Alternate-HTTP",
        9000: "CSlistener", 9090: "Web-Admin", 10000: "Webmin",
        11211: "Memcached", 27017: "MongoDB", 50000: "SAP-Router",
        **{i: 'Dynamic/RPC' for i in range(49152, 49167)}
    }
    return mapping.get(port, "Unknown")

# Interactive menu function
def interactive_menu():
    while True:
        target = input(f"\n{RED}Enter IP or domain (or 'q' to quit):{RESET} ").strip()
        if target.lower() in ['q', 'quit', 'exit']:
            print("Exiting interactive mode.")
            break
        ports = scan_ports(target)
        print_open_ports(ports)
        choice = input("Save report as (xml/json/pdf or skip): ").strip().lower()
        if choice in ['xml', 'json', 'pdf']:
            write_func = {'xml': write_xml_log, 'json': write_json_log, 'pdf': write_pdf_log}[choice]
            filename = f"portscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{choice}"
            path = os.path.join(LOG_DIR, filename)
            write_func(path, target, ports)
        else:
            print("Skipping log generation.")
        cont = input("\nScan another target? (y/n): ").strip().lower()
        if cont != 'y':
            print("Exiting interactive mode.")
            break

# Main entry
def main():
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    import argparse
    parser = argparse.ArgumentParser(description="Port Scanner Tool with Reporting")
    parser.add_argument("-t", "--target", help="IP or domain to scan")
    parser.add_argument("-f", "--format", choices=['xml','json','pdf'], help="Report format")
    args = parser.parse_args()

    if args.target:
        ports = scan_ports(args.target)
        print_open_ports(ports)
        if args.format:
            write_funcs = {'xml': write_xml_log, 'json': write_json_log, 'pdf': write_pdf_log}
            filename = f"portscan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.format}"
            path = os.path.join(LOG_DIR, filename)
            write_funcs[args.format](path, args.target, ports)
    else:
        interactive_menu()

if __name__ == '__main__':
    main()
