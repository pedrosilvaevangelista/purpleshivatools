# progress.py (Corrigido para ARP Poison)
import time
import threading
import shutil
import sys
import config as conf

class ARPProgressUpdater:
    def __init__(self, poisoner_instance=None):
        self.poisoner = poisoner_instance
        self._start_time = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
    def start(self):
        self._start_time = time.time()
        thread = threading.Thread(target=self._update_loop)
        thread.daemon = True
        thread.start()
        
    def stop(self):
        self._stop_event.set()
        
    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                if self.poisoner:
                    packets_sent = self.poisoner.packets_sent
                    target_ip = self.poisoner.target_ip
                    gateway_ip = self.poisoner.gateway_ip
                else:
                    packets_sent = 0
                    target_ip = "N/A"
                    gateway_ip = "N/A"
                    
            output = f"ARP Poisoning: {conf.BOLD}{target_ip}{conf.RESET} ↔ {conf.BOLD}{gateway_ip}{conf.RESET} | Packets: {conf.BOLD}{packets_sent}{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET}"
            
            # Limpar linha e escrever novo output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            
            time.sleep(1)
            
        # Quebrar linha quando parar
        sys.stdout.write("\n")
        sys.stdout.flush()

class SimpleProgressUpdater:
    def __init__(self, total_tasks=None):
        self.total_tasks = total_tasks
        self._start_time = None
        self._stop_event = threading.Event()
        self._tasks_completed = 0
        self._lock = threading.Lock()
        
    def start(self):
        self._start_time = time.time()
        thread = threading.Thread(target=self._update_loop)
        thread.daemon = True
        thread.start()
        
    def stop(self):
        self._stop_event.set()
        
    def increment(self):
        with self._lock:
            self._tasks_completed += 1
            
    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                completed = self._tasks_completed
                
            if self.total_tasks:
                percent = (completed / self.total_tasks) * 100
                output = f"Progress: {conf.BOLD}{percent:.2f}%{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET} | Tasks: {completed}/{self.total_tasks}"
            else:
                output = f"Completed: {conf.BOLD}{completed} tasks{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET}"
                
            # Limpar linha e escrever novo output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            
            time.sleep(1)
            
        # Quebrar linha quando parar
        sys.stdout.write("\n")
        sys.stdout.flush()