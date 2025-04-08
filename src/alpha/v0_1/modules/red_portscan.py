#!/usr/bin/env python3
# Port Scanner

import socket
import concurrent.futures
import sys
import time
import threading
import signal

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Global variables for real-time timer and thread control
stopTimer = False
progressLine = ""
timerThread = None
stdoutLock = threading.Lock()

# Total number of ports
totalPorts = 65535
openPorts = []


def UpdateTimer(startTime):
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write(f"\r{progressLine} | Duration: {BOLD}{elapsedFormatted}{RESET}")
            sys.stdout.flush()
        time.sleep(1)


def ScanPort(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = GetServiceName(port)
                vulnInfo = GetVulnerabilityInfo(port)
                return (port, service, vulnInfo)
        return None
    except:
        return None


def ScanPorts(target):
    global stopTimer, progressLine, timerThread, openPorts

    print(f"\n{RED}Initializing port scan on target:{RESET} {BOLD}{target}{RESET}")
    startTime = time.time()
    progressLine = f"Progress: {BOLD}0.00%{RESET} | Port: {BOLD}---{RESET} | Open Ports: {BOLD}0{RESET}"
    openPorts = []

    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
        futures = {executor.submit(ScanPort, target, port): port for port in range(1, totalPorts + 1)}
        for count, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            result = future.result()
            if result:
                openPorts.append(result)
            progress = (count / totalPorts) * 100
            portDisplay = result[0] if result else futures[future]
            progressLine = (f"Progress: {BOLD}{progress:.2f}%{RESET} | "
                            f"Port: {BOLD}{portDisplay}{RESET} | "
                            f"Open Ports: {BOLD}{len(openPorts)}{RESET}")
            with stdoutLock:
                sys.stdout.write(f"\r{progressLine}")
                sys.stdout.flush()

    stopTimer = True
    timerThread.join()

    print()
    return openPorts


def PrintOpenPorts(ports):
    print("\nOpen ports found:")
    print("Port\tService\tVulnerabilities")
    print("----------------------------------------------")
    for port, service, vuln in ports:
        print(f"{port}\t{service}\t{vuln if vuln else 'None'}")


def menu():
    target = input(f"\n{RED}Enter IP or domain:{RESET} ").strip()
    ports = ScanPorts(target)
    PrintOpenPorts(ports)


def terminal():
    import argparse
    parser = argparse.ArgumentParser(
        description="Port Scanner Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="IP or domain to scan")
    args = parser.parse_args()
    ports = ScanPorts(args.target)
    PrintOpenPorts(ports)


def SignalHandler(sig, frame):
    global stopTimer, timerThread
    print(f"\n{RED}Stopping the port scan...{RESET}")
    stopTimer = True
    if timerThread is not None and timerThread.is_alive():
        timerThread.join()
    sys.exit(0)


def GetServiceName(port):
    serviceMap = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
        445: "SMB", 1433: "MS-SQL", 1521: "Oracle", 2049: "NFS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
        5353: "mDNS", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached"
    }
    return serviceMap.get(port, "Unknown")


def GetVulnerabilityInfo(port):
    vulnDb = {
        21: "Anonymous login, Brute Force, Old version exploits",
        22: "Brute Force SSH, Shellshock, Weak keys",
        23: "Default credentials, Unencrypted communication",
        80: "SQL Injection, XSS, Directory Traversal",
        443: "Heartbleed, POODLE, Invalid certificates",
        445: "EternalBlue, SMB Exploits, Ransomware",
        3389: "BlueKeep, Credential Theft",
        5900: "Weak auth, VNC exploits"
    }
    return vulnDb.get(port, None)


def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()
    

if __name__ == "__main__":
    main()
