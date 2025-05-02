#!/usr/bin/env python3
# Ping Sweep Tool with Enhanced Reporting and Security Recommendations

import argparse
import logging
import os
import sys
import signal
import time
import threading
import json
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from scapy.all import IP, ICMP, sr1

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Security recommendations specific to Ping Sweep
RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "ICMP Rate Limiting",
        "severity": "High",
        "description": (
            "Limit the rate of ICMP Echo Replies to mitigate large-scale ping sweeps "
            "and reduce risk of denial-of-service conditions."
        ),
        "metrics": {
            "max_icmp_per_sec": 100,
            "dropped_icmp_ratio": ">=95%"
        },
        "sources": [
            "Cisco: ICMP rate-limit configuration",
            "RFC 1812: Requirements for IP Version 4 Routers"
        ]
    },
    {
        "id": 2,
        "title": "Firewall ICMP Filtering",
        "severity": "Medium",
        "description": (
            "Deploy firewall rules to allow ICMP only from trusted subnets or hosts, "
            "blocking unsolicited Echo Replies."
        ),
        "metrics": {
            "filtered_hosts": "percentage of hosts filtering ICMP",
            "rule_coverage": "scope of trusted zones"
        },
        "sources": [
            "iptables: icmp-filtering guide",
            "Palo Alto Networks: ICMP security best practices"
        ]
    },
    {
        "id": 3,
        "title": "Network Segmentation",
        "severity": "Low",
        "description": (
            "Segment critical assets into isolated VLANs or subnets, reducing the "
            "scope of ping sweeps across sensitive networks."
        ),
        "metrics": {
            "segments_deployed": "number of isolated VLANs",
            "attack_surface_reduction": "percentage"
        },
        "sources": [
            "NIST SP 800-125: Network isolation guidelines",
            "Academic study: VLAN effectiveness in segmentation"
        ]
    }
]

# Directory for logs
LOG_DIR = os.path.expanduser("/var/log/purpleshivatoolslog")
os.makedirs(LOG_DIR, exist_ok=True)

# Suppress scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Global timer control\stopTimer = False
progressLine = ""
stdoutLock = threading.Lock()
timerThread = None

# Ensure running as root for raw socket operations
if os.geteuid() != 0:
    print(f"{RED}Error: This tool must be run as root.{RESET}")
    sys.exit(1)

# Timer thread to display elapsed time
def update_timer(start_time):
    global stopTimer
    while not stopTimer:
        elapsed = time.time() - start_time
        elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsed_formatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

# Scan a single host with ICMP
def scan_host(ip):
    pkt = IP(dst=str(ip)) / ICMP()
    resp = sr1(pkt, timeout=1, verbose=False)
    return (str(ip), bool(resp))

# Main function to perform ping sweep
def ping_sweep(ip_range):
    global stopTimer, progressLine, timerThread
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        print(f"{RED}Invalid IP range format. Use something like 192.168.1.0/24{RESET}")
        return []

    print(f"\nInitializing ping sweep on the IP range {ip_range}")
    active_hosts = []
    total_hosts = len(hosts)
    start_time = time.time()
    progressLine = f"Progress: {BOLD}0.00%{RESET} | Host: {BOLD}---{RESET} | Active Hosts: {BOLD}0{RESET}"

    # Start timer thread
    stopTimer = False
    timerThread = threading.Thread(target=update_timer, args=(start_time,))
    timerThread.start()

    # Concurrent scan
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(scan_host, hosts)
        for count, (ip, alive) in enumerate(results, start=1):
            if alive:
                active_hosts.append(ip)
            progress = (count / total_hosts) * 100
            progressLine = (
                f"Progress: {BOLD}{progress:.2f}%{RESET} | "
                f"Host: {BOLD}{ip}{RESET} | "
                f"Active Hosts: {BOLD}{len(active_hosts)}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    # Stop timer thread
    stopTimer = True
    timerThread.join()
    print()
    return active_hosts

# Display active hosts
def print_hosts(hosts):
    print(f"\nFound active hosts:")
    print("IP Address")
    print("-----------------------------------------")
    for ip in hosts:
        print(f"{GREEN}{ip}{RESET}")

# Write XML log including recommendations
def write_xml_log(filepath, hosts):
    root = ET.Element("PingSweepLog")
    ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
    ET.SubElement(root, "TotalHosts").text = str(len(hosts))
    hosts_el = ET.SubElement(root, "Hosts")
    for ip in hosts:
        ET.SubElement(hosts_el, "Host").text = ip

    recs_el = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        r = ET.SubElement(recs_el, "Recommendation")
        ET.SubElement(r, "ID").text = str(rec["id"])
        ET.SubElement(r, "Title").text = rec["title"]
        ET.SubElement(r, "Severity").text = rec["severity"]
        ET.SubElement(r, "Description").text = rec["description"]
    tree = ET.ElementTree(root)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    print(f"\n{BOLD}XML log written to:{RESET} {filepath}")

# Write JSON log including recommendations
def write_json_log(filepath, hosts):
    data = {
        "timestamp": datetime.now().isoformat(),
        "total_hosts": len(hosts),
        "hosts": hosts,
        "security_recommendations": RECOMMENDATIONS
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"\n{BOLD}JSON log written to:{RESET} {filepath}")

# Write PDF report including recommendations
def write_pdf_log(filepath, hosts):
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title and meta\    elements.append(Paragraph("Ping Sweep Report", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Total Active Hosts: {len(hosts)}", styles['Normal']))
    elements.append(Spacer(1, 12))

    # Hosts table
    elements.append(Paragraph("Active Hosts", styles['Heading2']))
    table_data = [['IP Address']]
    for ip in hosts:
        table_data.append([ip])
    table = Table(table_data, colWidths=[500])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5'))
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    # Recommendations
    elements.append(Paragraph("Security Recommendations", styles['Heading2']))
    for rec in RECOMMENDATIONS:
        elements.append(Paragraph(f"<b>{rec['title']} (Severity: {rec['severity']})</b>", styles['BodyText']))
        elements.append(Paragraph(rec['description'], styles['BodyText']))
        # Metrics
        metrics_lines = [f"- {k}: {v}" for k, v in rec['metrics'].items()]
        elements.append(Paragraph("<i>Metrics:</i><br/>" + "<br/>".join(metrics_lines), styles['BodyText']))
        # Sources
        sources_lines = [f"- {s}" for s in rec['sources']]
        elements.append(Paragraph("<i>Sources:</i><br/>" + "<br/>".join(sources_lines), styles['BodyText']))
        elements.append(Spacer(1, 12))

    # Build document
    doc.build(elements)
    print(f"\n{BOLD}PDF log written to:{RESET} {filepath}")

# Unified log writer
def write_logs(hosts, fmt):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'xml':
        path = os.path.join(LOG_DIR, f"pingsweep_{ts}.xml")
        write_xml_log(path, hosts)
    elif fmt == 'json':
        path = os.path.join(LOG_DIR, f"pingsweep_{ts}.json")
        write_json_log(path, hosts)
    elif fmt == 'pdf':
        path = os.path.join(LOG_DIR, f"pingsweep_{ts}.pdf")
        write_pdf_log(path, hosts)

# CLI and menu

def menu():
    ip_range = input(f"\n{RED}IP range (e.g. 192.168.1.0/24): {RESET}")
    hosts = ping_sweep(ip_range)
    print_hosts(hosts)
    choice = input("Save report as (xml/json/pdf): ").strip().lower()
    if choice in ('xml', 'json', 'pdf'):
        write_logs(hosts, choice)
    else:
        print(f"{RED}Invalid choice, skipping log generation.{RESET}")


def terminal():
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool with Enhanced Reporting and Security Recommendations",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True,
                        help="IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-f", "--format", choices=['xml','json','pdf'],
                        help="Log format to save report")
    args = parser.parse_args()
    hosts = ping_sweep(args.ip_range)
    print_hosts(hosts)
    if args.format:
        write_logs(hosts, args.format)

# Graceful shutdown
def signal_handler(sig, frame):
    global stopTimer, timerThread
    print(f"\n{RED}Stopping ping sweep...{RESET}")
    stopTimer = True
    if timerThread and timerThread.is_alive():
        timerThread.join()
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()
