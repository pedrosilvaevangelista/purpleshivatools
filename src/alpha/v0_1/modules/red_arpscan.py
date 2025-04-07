#!/usr/bin/env python3
# ARP Scan

import argparse
from scapy.all import ARP, Ether, srp
import sys
import signal
import time
import threading

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

stopTimer = False
timerThread = None
stdoutLock = threading.Lock()
progressLine = ""

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

def ArpScan(ipRange):
    global stopTimer, timerThread, progressLine
    # Parse the IP network (assumes a /24 range)
    ipNetwork = list(ipRange)
    dot = 0
    i = 0
    remove = False
    for c in ipNetwork:
        if c == ".":
            dot += 1
            if dot == 3:
                remove = True
        if remove and c != ".":
            ipNetwork[i] = ""
        i += 1
    ipNetwork = ''.join(ipNetwork)
    
    print(f"\nInitializing ARP scan on the IP range {ipRange}")
    devices = []
    totalIps = 254
    startTime = time.time()
    
    progressLine = f"Progress: {BOLD}0.00%{RESET} | IP: {BOLD}---{RESET} | Devices Found: {BOLD}0{RESET}"
    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()
    
    for count, host in enumerate(range(1, 255), start=1):
        ip = f"{ipNetwork}{host}"
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=1, verbose=False)[0]
        if result:
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        progress = (count / totalIps) * 100
        deviceCount = len(devices)
        progressLine = (f"Progress: {BOLD}{progress:.2f}%{RESET} | "
                        f"IP: {BOLD}{ip}{RESET} | "
                        f"Devices Found: {BOLD}{deviceCount}{RESET}")
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine}")
            sys.stdout.flush()
            
    stopTimer = True
    timerThread.join()
    print()
    return devices

def PrintDevices(devices):
    print("\nFound devices:")
    print("IP\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

def menu():
    ipRange = input(f"\n{RED}IP range (e.g. 192.168.1.0/24):{RESET} ")
    devices = ArpScan(ipRange)
    PrintDevices(devices)

def terminal():
    parser = argparse.ArgumentParser(
        description="ARP Scan Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ip_range", required=True,
                        help="IP range (e.g. 192.168.1.0/24)")
    args = parser.parse_args()
    devices = ArpScan(args.ip_range)
    PrintDevices(devices)

def signalHandler(sig, frame):
    print(f"\n{RED}Stopping ARP Scan...{RESET}")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
