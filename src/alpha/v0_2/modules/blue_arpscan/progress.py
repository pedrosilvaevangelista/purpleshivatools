import time
import threading
import shutil
import sys
from modules import config as conf

class ProgressUpdater:
    def __init__(self, total_tasks=None, silent=False):
        self.total_tasks = total_tasks
        self.silent = silent  # Add silent mode
        self._start_time = None
        self._stop_event = threading.Event()
        self._tasks_completed = 0
        self._lock = threading.Lock()
        self._thread = None
    
    def start(self):
        self._start_time = time.time()
        if not self.silent:  # Only start thread if not in silent mode
            self._thread = threading.Thread(target=self._update_loop)
            self._thread.daemon = True
            self._thread.start()
    
    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)  # Wait for thread to finish cleanly
    
    def increment(self):
        with self._lock:
            self._tasks_completed += 1
    
    def get_progress_info(self):
        """Get current progress information without printing"""
        elapsed = time.time() - self._start_time if self._start_time else 0
        elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
        
        with self._lock:
            completed = self._tasks_completed
            
        if self.total_tasks:
            percent = (completed / self.total_tasks) * 100
            return {
                'completed': completed,
                'total': self.total_tasks,
                'percent': percent,
                'elapsed': elapsed_formatted,
                'elapsed_seconds': elapsed
            }
        else:
            return {
                'completed': completed,
                'total': None,
                'percent': None,
                'elapsed': elapsed_formatted,
                'elapsed_seconds': elapsed
            }
    
    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                completed = self._tasks_completed
            
            if self.total_tasks:
                percent = (completed / self.total_tasks) * 100
                output = f"Progress: {conf.BOLD}{percent:.2f}%{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET} | IPs: {completed}/{self.total_tasks}"
            else:
                output = f"Scanned: {conf.BOLD}{completed} IPs{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET}"
            
            # Clear line and write new output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            
            time.sleep(1)
        
        # Clear the progress line when stopping
        terminal_width = shutil.get_terminal_size().columns
        sys.stdout.write("\r" + " " * terminal_width + "\r")
        sys.stdout.flush()