#!/usr/bin/env python3
# Ping Sweep

import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, sr1
import sys
import signal
import time
import threading

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global variables for real-time timer
stopTimer = False
progressLine = ""

def updateTimer(startTime):
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsedFormatted}{RESET}")
        sys.stdout.flush()
        time.sleep(1)

def PingSweep(ipRange):
    global stopTimer, progressLine

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
    print(f"\nInitializing ping sweep on the IP range {ipRange}")
    activeHosts = []
    totalIps = 254 
    startTime = time.time()

    # Start the timer thread
    stopTimer = False
    timerThread = threading.Thread(target=updateTimer, args=(startTime,))
    timerThread.start()

    for count, host in enumerate(range(1, 255), start=1):
        ip = f"{ipNetwork}{host}"
        pkt = IP(dst=ip)/ICMP()
        response = sr1(pkt, timeout=1, verbose=False)
        if response: 
            activeHosts.append(ip)

        progress = (count / totalIps) * 100
        progressLine = f"Progress: {BOLD}{progress:.2f}%{RESET} | Host: {BOLD}{ip}{RESET}"

    # Stop the timer thread
    stopTimer = True
    timerThread.join()

    print()
    return activeHosts

def printHosts(hosts):
    print("\nActive hosts that have been found:")
    print("-----------------------------------------")
    for host in hosts:
        print(f"{host}")

def menu():
    ipRange = input(f"\n{RED}IP range (e.g. 192.168.1.0/24): {RESET}")
    hosts = PingSweep(ipRange)
    printHosts(hosts)

def terminal():
    parser = argparse.ArgumentParser(
        description="Ping Sweep Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--ipRange", required=True, 
                        help="IP range (e.g. 192.168.1.0/24)")
    args = parser.parse_args()
    hosts = PingSweep(args.ipRange)
    printHosts(hosts)

def signalHandler(sig, frame):
    print("\nStopping the attack")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
