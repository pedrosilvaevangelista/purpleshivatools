#!/usr/bin/env python3
# ARP Scan (Reconnaissance) + Reporting and Security Recommendations

import argparse
import sys
import signal
import time
import threading
import os
import xml.etree.ElementTree as ET
import json
import ipaddress
from datetime import datetime
from scapy.all import ARP, Ether, srp, conf
from concurrent.futures import ThreadPoolExecutor
from reportlab.lib.pagesizes import letter
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Line

# ANSI color codes
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global for user‑selected interface (None means default)
INTERFACE = None

RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "Dynamic ARP Inspection (DAI)",
        "severity": "High",
        "description": (
            "Validates ARP packets on untrusted ports using a default rate limit "
            "of 15 packets per second (pps), and intercepts, logs, and drops invalid ARPs."
        ),
        "specificDetails": {
            "Rate Limit": "15 pps",
            "Detection Success": "100%"
        },
        "sources": [
            "Cisco: default 15 pps rate on untrusted ports",
            "Academic research: 100% spoofing detection success in simulation"
        ]
    },
    {
        "id": 2,
        "title": "Port Security on Switches",
        "severity": "Medium",
        "description": (
            "Configures port security on switches to limit the number of MAC addresses "
            "per port and to restrict ARP traffic to prevent unauthorized access and mitigate ARP poisoning."
        ),
        "specificDetails": {
            "Max MAC Addresses": 2,
            "Allowed Age": "3600 seconds"
        },
        "sources": [
            "Cisco: Recommended port security settings",
            "Industry best practices: Limiting MAC addresses per port"
        ]
    },
    {
        "id": 3,
        "title": "VLAN Configuration and Segmentation",
        "severity": "High",
        "description": (
            "Configures VLANs to segment network traffic, isolating different departments or "
            "sensitive areas of the network to improve security and reduce the impact of potential attacks."
        ),
        "specificDetails": {
            "VLANs Configured": "10, 20, 30",
            "Purpose": "Finance, HR, Marketing department segmentation"
        },
        "sources": [
            "Cisco: VLAN configuration best practices",
            "Network security guidelines: VLAN segmentation for security"
        ]
    },
    {
        "id": 4,
        "title": "Vulnerability Scan and Remediation",
        "severity": "Critical",
        "description": (
            "Conducts a comprehensive vulnerability scan across the network to identify "
            "misconfigurations, open ports, and outdated software, ensuring that discovered vulnerabilities "
            "are prioritized and remediated promptly."
        ),
        "specificDetails": {
            "Scan Frequency": "Monthly",
            "High Priority Issues": "Unpatched critical vulnerabilities",
            "Remediation Timeline": "Within 48 hours of detection"
        },
        "sources": [
            "OWASP: Vulnerability scanning best practices",
            "NIST: Security scanning and remediation guidelines"
        ]
    }
]

logDir = "/var/log/purpleshivatoolslog"
os.makedirs(logDir, exist_ok=True)

timerThread = None
stopTimer = False
stdoutLock = threading.Lock()
progressLine = ""

if os.geteuid() != 0:
    print(f"{RED}Error: This script must be run as root.{RESET}")
    sys.exit(1)

# global to hold last scan info
scanInfo = {}

def SignalHandler(sig, frame):
    print(f"\n{RED}Stopping the attack...{RESET}")
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

def ScanIp(ip):
    arpRequest = ARP(pdst=str(ip))
    etherFrame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = etherFrame / arpRequest
    # if INTERFACE is set, tell scapy to use it
    if INTERFACE:
        result = srp(packet, timeout=1, verbose=False, iface=INTERFACE)[0]
    else:
        result = srp(packet, timeout=1, verbose=False)[0]
    return [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for snd, rcv in result] if result else []

def ArpScan(ipRange):
    global stopTimer, progressLine, scanInfo
    try:
        network = ipaddress.ip_network(ipRange, strict=False)
        hosts = list(network.hosts())
    except ValueError:
        print(f"{RED}Invalid IP range format. Use something like 192.168.1.0/24{RESET}")
        return []

    print(f"\nInitializing ARP scan on the IP range {ipRange} (iface={INTERFACE or 'default'})")
    devices = []
    totalIps = len(hosts)
    startTime = time.time()

    progressLine = f"Progress: {BOLD}0.00%{RESET} | IP: {BOLD}---{RESET} | Devices Found: {BOLD}0{RESET}"
    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ScanIp, ip): ip for ip in hosts}
        for count, future in enumerate(futures, start=1):
            found = future.result()
            if found:
                devices.extend(found)
            ip = futures[future]
            progress = (count / totalIps) * 100
            deviceCount = len(devices)
            progressLine = (
                f"Progress: {BOLD}{progress:.2f}%{RESET} | IP: {BOLD}{ip}{RESET} | Devices Found: {BOLD}{deviceCount}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    stopTimer = True
    timerThread.join()
    elapsed = time.time() - startTime
    scanInfo['ipRange'] = ipRange
    scanInfo['duration'] = elapsed
    print()
    return devices

def DetectArpSpoofing(devices):
    seen = {}
    for dev in devices:
        mac = dev['mac']
        ip = dev['ip']
        if mac in seen:
            print(f"{RED}[!] Possible ARP spoofing: MAC {mac} seen for IPs {seen[mac]} and {ip}{RESET}")
        else:
            seen[mac] = ip

def PrintDevices(devices):
    print("\nFound devices:\n")
    print("IP\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{GREEN}{device['ip']}{RESET}\t{device['mac']}")
    DetectArpSpoofing(devices)

def WriteXmlLog(filepath, devices):
    root = ET.Element("ARPScanLog")
    summary = ET.SubElement(root, "Summary")
    ET.SubElement(summary, "TotalHostsFound").text = str(len(devices))
    ET.SubElement(summary, "ScanStatus").text = "Success"
    ET.SubElement(summary, "IPRange").text = scanInfo.get('ipRange', 'n/a')
    ET.SubElement(summary, "Duration").text = str(scanInfo.get('duration', 0))

    hostsElem = ET.SubElement(root, "Hosts")
    for dev in devices:
        host = ET.SubElement(hostsElem, "Host")
        ET.SubElement(host, "IP").text = dev['ip']
        ET.SubElement(host, "MAC").text = dev['mac']

    recs = ET.SubElement(root, "SecurityRecommendations")
    for rec in RECOMMENDATIONS:
        recElem = ET.SubElement(recs, "Recommendation")
        ET.SubElement(recElem, "Title").text = rec["title"]
        ET.SubElement(recElem, "Severity").text = rec["severity"]
        ET.SubElement(recElem, "Description").text = rec["description"]

        # Add SpecificDetails as <Detail key="...">value</Detail>
        specific_details = rec.get("specificDetails", {})
        if specific_details:
            detailsElem = ET.SubElement(recElem, "SpecificDetails")
            for key, value in specific_details.items():
                # Add each detail as a <Detail> element with a 'key' attribute
                detailElem = ET.SubElement(detailsElem, "Detail")
                detailElem.set("key", key)
                detailElem.text = str(value)

        # Add sources for each recommendation
        sourcesElem = ET.SubElement(recElem, "Sources")
        for source in rec["sources"]:
            ET.SubElement(sourcesElem, "Source").text = source

    tree = ET.ElementTree(root)
    tree.write(filepath, encoding="utf-8", xml_declaration=True)
    print(f"\n{BOLD}XML log written to:{RESET} {filepath}")



def WriteJsonLog(filepath, devices):
    data = {
        "TotalHostsFound": len(devices),
        "Hosts": devices,
        "IPRange": scanInfo.get('ipRange', 'n/a'),
        "Duration": scanInfo.get('duration', 0),
        "SecurityRecommendations": []
    }

    for rec in RECOMMENDATIONS:
        recommendation = {
            "Title": rec["title"],
            "Severity": rec["severity"],
            "Description": rec["description"],
            "SpecificDetails": rec.get("specificDetails", {}),
            "Sources": rec["sources"]
        }
        data["SecurityRecommendations"].append(recommendation)

    # Write the final JSON to the file
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
        Paragraph("ARP Scan Report", titleStyle),
        Spacer(1, 10),
    ]))

    # — Intro block with purple line
    intro = (
        "This report was generated by the Purple Shiva Tools ARP Scan module. "
        "It documents active hosts discovered on the local network using ARP requests. "
        "Such scans can help detect unauthorized devices or early signs of ARP spoofing attacks. "
        "The results below show MAC and IP address pairs found during the scan. "
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
    tableData = [['IP Address','MAC Address']] + [[d['ip'],d['mac']] for d in devices]
    table = Table(tableData, colWidths=[250,250])
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

    # — Footer / additional monitoring block
    elements.append(KeepTogether([
        Spacer(1, 30),
        CreatePurpleLine(),
        Spacer(1, 30),
        Paragraph(
            f"Additional: Monitor hosts: {', '.join(d['ip'] for d in devices)}",
            bodyStyle
        ),
        Spacer(1, 30),
        CreatePurpleLine(),
        Spacer(1, 30),
    ]))

    doc.build(elements)
    print(f"\n{BOLD}PDF log written to:{RESET} {filepath}")

def WriteLogs(devices, fmt):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'xml':
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.xml")
        WriteXmlLog(path, devices)
    elif fmt == 'json':
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.json")
        WriteJsonLog(path, devices)
    elif fmt == 'pdf':
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.pdf")
        WritePdfLog(path, devices)
    elif fmt == 'all':
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.xml")
        WriteXmlLog(path, devices)
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.json")
        WriteJsonLog(path, devices)
        path = os.path.join(logDir, f"arpscanlog_{timestamp}.pdf")
        WritePdfLog(path, devices)
        
def menu():
    global INTERFACE
    ipRange = input(f"\n{RED}IP range (e.g. 192.168.1.0/24):{RESET} ")
    iface = input(f"{RED}Interface (leave blank for default):{RESET} ").strip()
    INTERFACE = iface if iface else None

    devices = ArpScan(ipRange)
    PrintDevices(devices)

    formatChoice = input(
        f"\nSave report as {BOLD}[XML]{RESET}, {BOLD}[JSON]{RESET}, {BOLD}[PDF]{RESET} or {BOLD}[ALL]{RESET} "
        "(leave blank for none): "
    ).strip().lower()
    if formatChoice in ('xml', 'json', 'pdf', 'all'):
        WriteLogs(devices, formatChoice)
    else:
        print(f"{RED}No log saved.{RESET}")

def terminal():
    global INTERFACE
    parser = argparse.ArgumentParser(
        description="ARP Scan Tool", formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True, help="IP range (e.g. 192.168.1.0/24)")
    parser.add_argument("-f", "--format", choices=['xml', 'json', 'pdf', 'all'], help="Log format to save report")
    parser.add_argument("-I", "--interface", help="Network interface to send packets (e.g. eth0)")
    args = parser.parse_args()

    INTERFACE = args.interface
    devices = ArpScan(args.ip_range)
    PrintDevices(devices)
    if args.format:
        WriteLogs(devices, args.format)

def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
