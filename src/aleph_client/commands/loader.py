import shutil
import threading
from itertools import cycle
from time import sleep


class Loader:
    def __init__(self, desc="Loading...", end="Done!"):
        self.desc = desc
        self.end = end
        self.steps = ["⢿", "⣻", "⣽", "⣾", "⣷", "⣯", "⣟", "⡿"]
        self.done = False
        self._thread = None

    def start(self):
        if not self._thread:
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            print(f"\r{self.desc} {c}", flush=True, end="")
            sleep(0.1)

    def stop(self):
        self.done = True
        cols = shutil.get_terminal_size().columns
        print("\r" + " " * cols, end="", flush=True)
        print(f"\r{self.end}", flush=True)
        if self._thread:
            self._thread.join()
            self._thread = None

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop
