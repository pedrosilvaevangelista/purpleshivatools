import time
import threading
import shutil
import sys
from .. import config as conf

class ProgressUpdater:
    def __init__(self, total_passwords=None):
        self.total_passwords = total_passwords
        self._start_time = None
        self._stop_event = threading.Event()
        self._passwords_tested = 0
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
            self._passwords_tested += 1

    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsedFormatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

            with self._lock:
                tested = self._passwords_tested

            if self.total_passwords:
                percent = (tested / self.total_passwords) * 100
                output = f"Progress: {conf.BOLD}{percent:.5f}%{conf.RESET} | Duration: {conf.BOLD}{elapsedFormatted}{conf.RESET}"
            else:
                output = f"Tested: {conf.BOLD}{tested} passwords{conf.RESET} | Duration: {conf.BOLD}{elapsedFormatted}{conf.RESET}"

            sys.stdout.write("\r" + " " * shutil.get_terminal_size().columns)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            time.sleep(1)

        sys.stdout.write("\n")
        sys.stdout.flush()
