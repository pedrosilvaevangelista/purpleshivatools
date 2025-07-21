# progress.py pingsweep
import time
import threading
import shutil
import sys
from modules import config as conf

class ProgressUpdater:
    def __init__(self, total_tasks=None, show_rate=True, show_eta=True):
        """Initializes the progress updater"""
        self.total_tasks = total_tasks
        self.show_rate = show_rate
        self.show_eta = show_eta
        self._start_time = None
        self._stop_event = threading.Event()
        self._tasks_completed = 0
        self._active_hosts = 0
        self._lock = threading.Lock()
        self._thread = None

    def start(self):
        """Starts the progress monitor"""
        if self._thread and self._thread.is_alive():
            return
            
        self._start_time = time.time()
        self._stop_event.clear()
        
        self._thread = threading.Thread(target=self._update_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stops the progress monitor"""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        sys.stdout.write("\n")
        sys.stdout.flush()

    def increment(self, active_found=False):
        """Increments the count of completed tasks"""
        with self._lock:
            self._tasks_completed += 1
            if active_found:
                self._active_hosts += 1

    def set_active_count(self, count):
        """Sets the number of active hosts found"""
        with self._lock:
            self._active_hosts = count

    def get_stats(self):
        """Returns current statistics"""
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 0
            rate = self._tasks_completed / elapsed if elapsed > 0 else 0
            
            return {
                'completed': self._tasks_completed,
                'active_hosts': self._active_hosts,
                'elapsed': elapsed,
                'rate': rate,
                'total': self.total_tasks
            }

    def _calculate_eta(self, completed, elapsed):
        """Calculates estimated time to completion"""
        if not self.total_tasks or completed == 0:
            return "N/A"
        
        rate = completed / elapsed
        if rate == 0:
            return "N/A"
        
        remaining = self.total_tasks - completed
        eta_seconds = remaining / rate
        
        if eta_seconds < 60:
            return f"{eta_seconds:.0f}s"
        elif eta_seconds < 3600:
            minutes = eta_seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = eta_seconds / 3600
            return f"{hours:.1f}h"

    def _update_loop(self):
        """Main progress update loop"""
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))
            
            with self._lock:
                completed = self._tasks_completed
                active = self._active_hosts

            # Build progress line
            if self.total_tasks:
                percent = (completed / self.total_tasks) * 100
                output = f"Progress: {conf.BOLD}{percent:.2f}%{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET} | IPs: {completed}/{self.total_tasks}"
                
                # Add active hosts if any
                if active > 0:
                    output += f" | Active: {conf.GREEN}{active}{conf.RESET}"
                
                # Add rate if enabled
                if self.show_rate and elapsed > 1:
                    rate = completed / elapsed
                    output += f" | Rate: {conf.YELLOW}{rate:.1f}/s{conf.RESET}"
                
                # Add ETA if enabled
                if self.show_eta and completed > 0:
                    eta = self._calculate_eta(completed, elapsed)
                    output += f" | ETA: {conf.PURPLE}{eta}{conf.RESET}"
                    
            else:
                output = f"Scanned: {conf.BOLD}{completed} IPs{conf.RESET} | Duration: {conf.BOLD}{elapsed_formatted}{conf.RESET}"
                
                # Add active hosts if any
                if active > 0:
                    output += f" | Active: {conf.GREEN}{active}{conf.RESET}"
                
                # Add rate if enabled
                if self.show_rate and elapsed > 1:
                    rate = completed / elapsed
                    output += f" | Rate: {conf.YELLOW}{rate:.1f}/s{conf.RESET}"

            # Clear line and write new output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            
            time.sleep(1)

    def print_final_stats(self):
        """Prints final statistics after completion"""
        if not self._start_time:
            return
            
        stats = self.get_stats()
        elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(stats['elapsed']))
        
        print(f"\n{conf.PURPLE}{'='*50}{conf.RESET}")
        print(f"{conf.PURPLE}{conf.BOLD} FINAL STATISTICS {conf.RESET}")
        print(f"{conf.PURPLE}{'='*50}{conf.RESET}")
        
        if self.total_tasks:
            success_rate = (stats['completed'] / self.total_tasks) * 100
            print(f"Total IPs: {conf.CYAN}{self.total_tasks}{conf.RESET}")
            print(f"IPs scanned: {conf.CYAN}{stats['completed']}{conf.RESET} ({success_rate:.1f}%)")
        else:
            print(f"IPs scanned: {conf.CYAN}{stats['completed']}{conf.RESET}")
        
        print(f"Active hosts: {conf.GREEN}{stats['active_hosts']}{conf.RESET}")
        print(f"Total duration: {conf.BLUE}{elapsed_formatted}{conf.RESET}")
        
        if stats['rate'] > 0:
            print(f"Average rate: {conf.YELLOW}{stats['rate']:.2f} IPs/s{conf.RESET}")
        
        if self.total_tasks and stats['active_hosts'] > 0:
            discovery_rate = (stats['active_hosts'] / self.total_tasks) * 100
            print(f"Discovery rate: {conf.GREEN}{discovery_rate:.2f}%{conf.RESET}")


class QuietProgress:
    """Silent version of progress updater for use when verbose=False"""
    
    def __init__(self, total_tasks=None):
        self.total_tasks = total_tasks
        self._tasks_completed = 0
        self._active_hosts = 0
        self._start_time = None
        self._lock = threading.Lock()

    def start(self):
        self._start_time = time.time()

    def stop(self):
        pass

    def increment(self, active_found=False):
        with self._lock:
            self._tasks_completed += 1
            if active_found:
                self._active_hosts += 1

    def set_active_count(self, count):
        with self._lock:
            self._active_hosts = count

    def get_stats(self):
        with self._lock:
            elapsed = time.time() - self._start_time if self._start_time else 0
            rate = self._tasks_completed / elapsed if elapsed > 0 else 0
            
            return {
                'completed': self._tasks_completed,
                'active_hosts': self._active_hosts,
                'elapsed': elapsed,
                'rate': rate,
                'total': self.total_tasks
            }

    def print_final_stats(self):
        # Does not print anything in silent mode
        pass
