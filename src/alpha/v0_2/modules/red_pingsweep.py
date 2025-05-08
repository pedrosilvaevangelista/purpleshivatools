#!/usr/bin/env python3
# Ping Sweep (Reconnaissance) + Reporting and Security Recommendations

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
from reportlab.lib.pagesizes import letter
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Line
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
        "specificDetails": {
            "Max ICMP per Second": 100,
            "Dropped ICMP Ratio": ">=95%"
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
        "specificDetails": {
            "Filtered Hosts": "Percentage of hosts filtering ICMP",
            "Rule Coverage": "Scope of trusted zones"
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
        "specificDetails": {
            "Segments Deployed": "Number of isolated VLANs",
            "Attack Surface Reduction": "Percentage"
        },
        "sources": [
            "NIST SP 800-125: Network isolation guidelines",
            "Academic study: VLAN effectiveness in segmentation"
        ]
    }
]

# Directory for logs
logDir = os.path.expanduser("/var/log/purpleshivatoolslog")
os.makedirs(logDir, exist_ok=True)

# Suppress scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if os.geteuid() != 0:
    print(f"{RED}Error: This script must be run as root.{RESET}")
    sys.exit(1)

# Global timer control
stopTimer = False
progressLine = ""
stdoutLock = threading.Lock()
timerThread = None
scanInfo = {}  # To store scan metadata like duration

def SignalHandler(sig, frame):
    global stopTimer
    print(f"\n{RED}Stopping the attack...{RESET}")
    stopTimer = True
    sys.exit(0)

signal.signal(signal.SIGINT, SignalHandler)

def UpdateTimer(startTime):
    global stopTimer
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsedFormatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

def ScanHost(ip):
    pkt = IP(dst=str(ip))/ICMP()
    resp = sr1(pkt, timeout=1, verbose=False)
    return (str(ip), bool(resp))

def PingSweep(ipRange):
    global stopTimer, progressLine, timerThread, scanInfo
    try:
        network = ipaddress.ip_network(ipRange, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        print(f"{RED}Invalid IP range format. Use something like 192.168.1.0/24{RESET}")
        return []

    print(f"\nInitializing ping sweep on the IP range {ipRange}")
    activeHosts = []
    totalHosts = len(hosts)
    startTime = time.time()
    progressLine = f"Progress: {BOLD}0.00%{RESET} | Host: {BOLD}---{RESET} | Active Hosts: {BOLD}0{RESET}"

    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ScanHost, hosts)
        for count, (ip, alive) in enumerate(results, start=1):
            if alive:
                activeHosts.append(ip)
            progress = (count / totalHosts) * 100
            progressLine = (
                f"Progress: {BOLD}{progress:.2f}%{RESET} | "
                f"Host: {BOLD}{ip}{RESET} | "
                f"Active Hosts: {BOLD}{len(activeHosts)}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    stopTimer = True
    timerThread.join()
    scanInfo['ipRange'] = ipRange
    scanInfo['duration'] = time.time() - startTime
    print()
    return activeHosts

def PrintHosts(hosts):
    print("\nFound active hosts:\n")
    print("IP Address")
    print("-----------------------------------------")
    for ip in hosts:
        print(f"{GREEN}{ip}{RESET}")

def WriteXmlLog(filepath, hosts):
    root = ET.Element("PingSweepLog")
    summary = ET.SubElement(root, "Summary")
    ET.SubElement(summary, "TotalHostsFound").text = str(len(hosts))
    ET.SubElement(summary, "ScanStatus").text = "Success"
    ET.SubElement(summary, "IPRange").text = scanInfo.get('ipRange', 'n/a')
    ET.SubElement(summary, "Duration").text = str(scanInfo.get('duration', 0))

    hostsElem = ET.SubElement(root, "Hosts")
    for ip in hosts:
        ET.SubElement(hostsElem, "Host").text = ip

    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        recElem = ET.SubElement(recs, "Recommendation")
        ET.SubElement(recElem, "Title").text = rec["title"]
        ET.SubElement(recElem, "Severity").text = rec["severity"]
        ET.SubElement(recElem, "Description").text = rec["description"]

        details = rec.get("specificDetails", {})
        if details:
            detailsElem = ET.SubElement(recElem, "SpecificDetails")
            for key, value in details.items():
                detailElem = ET.SubElement(detailsElem, "Detail")
                detailElem.set("key", key)
                detailElem.text = str(value)

        sourcesElem = ET.SubElement(recElem, "Sources")
        for source in rec["sources"]:
            ET.SubElement(sourcesElem, "Source").text = source

    tree = ET.ElementTree(root)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    print(f"\n{BOLD}XML log written to:{RESET} {filepath}")

def WriteJsonLog(filepath, hosts):
    data = {         
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tool": "Purple Shiva Tools: ARP Spoofing (Main-in-the-middle) attack",
        },
        "totalHosts": len(hosts),
        "hosts": hosts,
        "ipRange": scanInfo.get('ipRange', 'n/a'),
        "duration": scanInfo.get('duration', 0),
        "securityRecommendations": RECOMMENDATIONS
    }
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"\n{BOLD}JSON log written to:{RESET} {filepath}")

def AddPageInfo(canvas, doc):
    scriptDir = os.path.dirname(os.path.abspath(__file__))
    mainDir = os.path.abspath(os.path.join(scriptDir, '../../../..'))
    bannerPath = os.path.join(mainDir, 'docs', 'reportbanner.png')

    pageWidth, pageHeight = letter
    banner = ImageReader(bannerPath)
    bannerHeight = (pageWidth * 80) / 500
    canvas.drawImage(banner, 0, pageHeight - bannerHeight, width=pageWidth, height=bannerHeight)

    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(pageWidth - 40, 20, f"Page {doc.page}")

def WritePdfLog(filepath, devices):
    def CreatePurpleLine(width=550, thickness=0.5):
        usableWidth = letter[0] - 36 - 36
        startX = (usableWidth - width) / 2
        line = Line(startX, 0, startX + width, 0)
        line.strokeColor = colors.HexColor('#461f6b')
        line.strokeWidth = thickness
        drawing = Drawing(usableWidth, thickness)
        drawing.add(line)
        return drawing

    # styles
    styles = getSampleStyleSheet()
    titleStyle = ParagraphStyle(
        'TitleStyle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#461f6b'),
        alignment=1
    )
    introStyle = ParagraphStyle(
        'IntroStyle',
        parent=styles['BodyText'],
        fontSize=12, alignment=1
    )
    bodyStyle = ParagraphStyle(
        'BodyStyle',
        parent=styles['BodyText'],
        fontSize=12, alignment=0
    )

    # page/frame setup
    pageWidth, pageHeight = letter
    bannerHeight = (pageWidth * 80) / 500
    leftMargin, rightMargin, topMargin, bottomMargin = 36, 36, 30, 30
    frameHeight = pageHeight - bannerHeight - topMargin - bottomMargin
    frame = Frame(leftMargin, bottomMargin,
                  pageWidth - leftMargin - rightMargin,
                  frameHeight)

    doc = BaseDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=leftMargin, rightMargin=rightMargin,
        topMargin=topMargin, bottomMargin=bottomMargin
    )
    doc.addPageTemplates([PageTemplate(
        id='WithBanner', frames=[frame], onPage=AddPageInfo
    )])

    elements = []

    # — Title block
    elements.append(KeepTogether([
        Paragraph("Ping Sweep Report", titleStyle),
        Spacer(1, 10),
    ]))
    
    # — Intro block with purple line
    intro = (
        "This report was generated by the Purple Shiva Tools Ping Sweep module. "
        "It documents active hosts discovered on the network using ICMP echo requests. "
        "Such scans help identify live hosts and network topology."
        "<br/><br/>"
        'More at <font color="#461f6b"><b><u>'
        '<link href="https://github.com/PurpleShivaTeam/purpleshivatools">'
        "https://github.com/PurpleShivaTeam/purpleshivatools"
        '</link></u></b></font>'
    )

    elements.append(KeepTogether([
        Paragraph(intro, introStyle),
        Spacer(1, 30),
        CreatePurpleLine(),
        Spacer(1, 30),
    ]))

    # — Date & count block
    ipr = scanInfo.get('ipRange', 'n/a')
    dur = scanInfo.get('duration', 0)
    hrs, rem = divmod(int(dur), 3600)
    mins, secs = divmod(rem, 60)
    durStr = f"{hrs:d}:{mins:02d}:{secs:02d}"

    elements.append(KeepTogether([
        Paragraph(f"Date: {datetime.now():%Y-%m-%d %H:%M:%S}", bodyStyle),
        Spacer(1, 10),
        Paragraph(f"Total hosts found: {len(devices)}", bodyStyle),
        Spacer(1, 10),
        Paragraph(f"<b>IP Range:</b> {ipr}", bodyStyle),
        Paragraph(f"<b>Scan Duration:</b> {durStr}", bodyStyle),
        Spacer(1, 30),
        CreatePurpleLine(),
        Spacer(1, 30),
    ]))

    # — Table block
    tableData = [['IP Address']] + [[d] for d in devices]
    table = Table(tableData, colWidths=[250])
    table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#461f6b')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('GRID',(0,0),(-1,-1),0.5,colors.grey),
        ('BACKGROUND',(0,1),(-1,-1),colors.HexColor('#f5f5f5')),
    ]))
    elements.append(KeepTogether([
        Paragraph("Discovered Hosts", titleStyle),
        Spacer(1, 10),
        table,
        Spacer(1, 30),
        CreatePurpleLine(),
        Spacer(1, 30),
    ]))

    # — Security Recommendations block (with heading)
    firstRec = True
    for rec in RECOMMENDATIONS:
        recBlock = []
        if firstRec:
            recBlock += [
                Paragraph("Security Recommendations", titleStyle),
                Spacer(1, 10),
            ]
            firstRec = False

        # Start the recommendation block with a bullet point
        recBlock += [
            Paragraph(f"• <b>{rec['title']}</b> (Severity: {rec['severity']})", bodyStyle),
            Spacer(1, 5),
        ]

        # Indent the description and details using HTML non-breaking spaces (&nbsp;)
        indent = "&nbsp;" * 6

        recBlock += [
            Paragraph(f"{indent}<i>{rec['description']}</i>", bodyStyle),
            Spacer(1, 5),
        ]

        # Add specific details (formerly metrics)
        details = rec.get('specificDetails', {})
        if details:
            detail_lines = "<br/>".join([f"{indent}{key}: {value}" for key, value in details.items()])
            recBlock += [
                Paragraph(f"{indent}<i>Details:</i><br/>{detail_lines}", bodyStyle),
                Spacer(1, 5),
            ]

        # Numbered sources
        numbered_sources = "<br/>".join([f"{indent}{i+1}. {source}" for i, source in enumerate(rec['sources'])])
        recBlock += [
            Paragraph(f"{indent}<i>Sources:</i><br/>{numbered_sources}", bodyStyle),
            Spacer(1, 15),
        ]
        elements.append(KeepTogether(recBlock))

    doc.build(elements)
    print(f"\n{BOLD}PDF log written to:{RESET} {filepath}")

def WriteLogs(devices, fmt):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'xml':
        path = os.path.join(logDir, f"pingsweep_{timestamp}.xml")
        WriteXmlLog(path, devices)
    elif fmt == 'json':
        path = os.path.join(logDir, f"pingsweep_{timestamp}.json")
        WriteJsonLog(path, devices)
    elif fmt == 'pdf':
        path = os.path.join(logDir, f"pingsweep_{timestamp}.pdf")
        WritePdfLog(path, devices)
    elif fmt == 'all':
        path = os.path.join(logDir, f"pingsweep_{timestamp}.xml")
        WriteXmlLog(path, devices)
        path = os.path.join(logDir, f"pingsweep_{timestamp}.json")
        WriteJsonLog(path, devices)
        path = os.path.join(logDir, f"pingsweep_{timestamp}.pdf")
        WritePdfLog(path, devices)

def menu():
    ipRange = input(f"\n{RED}IP range (e.g. 192.168.1.0/24): {RESET}")
    devices = PingSweep(ipRange)
    PrintHosts(devices)

    formatChoice = input(
        f"\nSave report as {BOLD}[XML]{RESET}, {BOLD}[JSON]{RESET}, {BOLD}[PDF]{RESET} or {BOLD}[ALL]{RESET} "
        "(leave blank for none): "
    ).strip().lower()
    if formatChoice in ('xml', 'json', 'pdf', 'all'):
        WriteLogs(devices, formatChoice)
    else:
        print(f"{RED}No log saved.{RESET}")

def terminal():
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool", 
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True, help="IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-f", "--format", choices=['xml', 'json', 'pdf', 'all'], help="Log format to save report")
    args = parser.parse_args()

    devices = PingSweep(args.ip_range)
    PrintHosts(devices)
    if args.format:
        WriteLogs(devices, args.format)

def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == '__main__':
    main()