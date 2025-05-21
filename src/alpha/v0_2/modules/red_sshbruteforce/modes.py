import os
import argparse
from .sshbruteforce import BruteForceSsh
import config as conf

BaseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # adjust as needed

def InteractiveMode():
    ip = input(f"\n{conf.RED}Target IP: {conf.RESET}").strip()
    username = input(f"{conf.RED}Username: {conf.RESET}").strip()
    passwordFile = input(f"{conf.RED}Password file [passwords.txt]: {conf.RESET}").strip() or "passwords.txt"
    mode = input(f"{conf.RED}Attack mode - slow or custom [slow]: {conf.RESET}").strip().lower() or "slow"
    reportFormat = input(f"{conf.RED}Report format (pdf/json/xml) [pdf]: {conf.RESET}").strip().lower() or None

    delay = 0.1
    if mode == "custom":
        delayInput = input(f"{conf.RED}Delay between attempts in custom mode (seconds, e.g. 0.1) [0.1]: {conf.RESET}").strip()
        delay = float(delayInput) if delayInput else 0.1

    BruteForceSsh(ip, username, passwordFile, mode=mode, reportFormat=reportFormat, baseDir=BaseDir, delay=delay)

def TerminalMode():
    parser = argparse.ArgumentParser(description="SSH Brute Force Attack Tool")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-u", "--username", required=True, help="Username for SSH login")
    parser.add_argument("-p", "--passwordFile", required=True, help="Path to password list file")
    parser.add_argument("-m", "--mode", choices=["slow", "custo"], default="slow", help="Attack mode: slow or custom")
    parser.add_argument("-r", "--reportFormat", choices=["pdf", "json", "xml"], default="pdf", help="Report format")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between attempts in custom mode (seconds)")
    args = parser.parse_args()

    BruteForceSsh(args.ip, args.username, args.passwordFile, mode=args.mode,
                  reportFormat=args.reportFormat, baseDir=BaseDir, delay=args.delay)

