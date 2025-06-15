# progress.py
import time
import threading
import shutil
import sys
import config as conf

class ProgressUpdater:
    def __init__(self):
        self._start_time = None
        self._stop_event = threading.Event()
        self._packets_sent = 0
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
            self._packets_sent += 1

    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

            with self._lock:
                packets = self._packets_sent

            output = f"ARP Spoof Ativo | Duração: {conf.BOLD}{elapsed_formatted}{conf.RESET} | Pacotes Enviados: {conf.BOLD}{packets}{conf.RESET}"

            # Limpar linha e escrever novo output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * terminal_width)
            sys.stdout.write("\r" + output)
            sys.stdout.flush()
            time.sleep(1)

        sys.stdout.write("\n")
        sys.stdout.flush()