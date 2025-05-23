import os
import argparse
from .sshbruteforce import BruteForceSsh
from .report import *
import config as conf

baseDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # adjust as needed

def InteractiveMode():
    ip = input(f"\n{conf.RED}Target IP: {conf.RESET}").strip()
    username = input(f"{conf.RED}Username: {conf.RESET}").strip()
    passwordFile = input(f"{conf.RED}Password file [passwords.txt]: {conf.RESET}").strip() or "passwords.txt"
    mode = input(f"{conf.RED}Attack mode - slow or custom [slow]: {conf.RESET}").strip().lower() or "slow"
    reportFormat = input(f"{conf.RED}Report format (pdf/json/xml) [pdf]: {conf.RESET}").strip().lower() or "pdf"

    delay = 0.1
    if mode == "custom":
        delayInput = input(f"{conf.RED}Delay between attempts in custom mode (seconds, e.g. 0.1) [0.1]: {conf.RESET}").strip()
        delay = float(delayInput) if delayInput else 0.1

    resultData = BruteForceSsh(ip, username, passwordFile, mode=mode, baseDir=baseDir, delay=delay)

    if not resultData:
        print(f"{conf.RED}[!] No result from brute force attack.{conf.RESET}")
        return

    if reportFormat == "json":
        WriteJsonLog(
            ip=resultData["ip"],
            username=resultData["username"],
            result=resultData["result"],
            passwordFile=resultData["passwordFile"],
            totalPasswords=resultData["totalPasswords"],
            totalAttempts=resultData["totalAttempts"],
            duration=resultData["duration"],
            outputDir=baseDir
        )
    elif reportFormat == "xml":
        WriteXmlLog(
            ip=resultData["ip"],
            username=resultData["username"],
            result=resultData["result"],
            passwordFile=resultData["passwordFile"],
            totalPasswords=resultData["totalPasswords"],
            totalAttempts=resultData["totalAttempts"],
            duration=resultData["duration"],
            outputDir=baseDir
        )
    elif reportFormat == "pdf":
        # Call your PDF report generation function here
        pass

def TerminalMode():
    parser = argparse.ArgumentParser(description="SSH Brute Force Attack Tool")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-u", "--username", required=True, help="Username for SSH login")
    parser.add_argument("-p", "--passwordFile", required=True, help="Path to password list file")
    parser.add_argument("-m", "--mode", choices=["slow", "custom"], default="slow", help="Attack mode: slow or custom")
    parser.add_argument("-r", "--reportFormat", choices=["pdf", "json", "xml"], default="pdf", help="Report format")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between attempts in custom mode (seconds)")
    args = parser.parse_args()

    resultData = BruteForceSsh(args.ip, args.username, args.passwordFile, mode=args.mode,
                              baseDir=baseDir, delay=args.delay)

    if not resultData:
        print(f"{conf.RED}[!] No result from brute force attack.{conf.RESET}")
        return

    if args.reportFormat == "json":
        WriteJsonLog(
            ip=resultData["ip"],
            username=resultData["username"],
            result=resultData["result"],
            passwordFile=resultData["passwordFile"],
            totalPasswords=resultData["totalPasswords"],
            totalAttempts=resultData["totalAttempts"],
            duration=resultData["duration"],
            outputDir=baseDir
        )
    elif args.reportFormat == "xml":
        WriteXmlLog(
            ip=resultData["ip"],
            username=resultData["username"],
            result=resultData["result"],
            passwordFile=resultData["passwordFile"],
            totalPasswords=resultData["totalPasswords"],
            totalAttempts=resultData["totalAttempts"],
            duration=resultData["duration"],
            outputDir=baseDir
        )
    elif args.reportFormat == "pdf":
        # Call your PDF report generation function here
        pass
