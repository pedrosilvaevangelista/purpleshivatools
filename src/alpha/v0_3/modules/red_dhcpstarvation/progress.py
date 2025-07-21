# progress.py
import time
import threading
import shutil
import sys
import config as conf

class DHCPProgressUpdater:
    def __init__(self):
        self._start_time = None
        self._stop_event = threading.Event()
        self._requests_sent = 0
        self._responses_received = 0
        self._unique_ips = 0
        self._lock = threading.Lock()

    def start(self):
        self._start_time = time.time()
        thread = threading.Thread(target=self._update_loop)
        thread.daemon = True
        thread.start()

    def stop(self):
        self._stop_event.set()

    def update_stats(self, requests_sent, responses_received, unique_ips):
        with self._lock:
            self._requests_sent = requests_sent
            self._responses_received = responses_received
            self._unique_ips = unique_ips

    def _update_loop(self):
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start_time
            elapsed_formatted = time.strftime("%H:%M:%S", time.gmtime(elapsed))

            with self._lock:
                requests = self._requests_sent
                responses = self._responses_received
                unique = self._unique_ips

            rate = requests / elapsed if elapsed > 0 else 0
            success_rate = (responses / requests * 100) if requests > 0 else 0

            output = f"{conf.PURPLE}[*] Enviados: {conf.GREEN}{requests}{conf.PURPLE} | "
            output += f"Respostas: {conf.GREEN}{responses}{conf.PURPLE} | "
            output += f"IPs únicos: {conf.GREEN}{unique}{conf.PURPLE} | "
            output += f"Taxa: {conf.GREEN}{rate:.1f}/s{conf.PURPLE} | "
            output += f"Sucesso: {conf.GREEN}{success_rate:.1f}%{conf.PURPLE} | "
            output += f"Tempo: {conf.GREEN}{elapsed_formatted}{conf.RESET}"

            # Limpar linha e escrever novo output
            terminal_width = shutil.get_terminal_size().columns
            sys.stdout.write("\r" + " " * min(terminal_width, 120))
            sys.stdout.write("\r" + output[:terminal_width-1])
            sys.stdout.flush()
            time.sleep(1)

        sys.stdout.write("\n")
        sys.stdout.flush()