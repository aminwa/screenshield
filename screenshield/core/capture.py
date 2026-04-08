import time
import threading
import mss
import mss.tools
from PIL import Image


class ScreenCapture:
    def __init__(self, fps=2, region=None):
        self.fps = fps
        self.region = region
        self._running = False
        self._thread = None

    def capture_frame(self) -> Image.Image:
        with mss.mss() as sct:
            mon = self.region if self.region else sct.monitors[0]
            shot = sct.grab(mon)
            return Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")

    def start(self, callback):
        self._running = True
        interval = 1.0 / self.fps

        def loop():
            while self._running:
                t0 = time.monotonic()
                frame = self.capture_frame()
                callback(frame)
                elapsed = time.monotonic() - t0
                wait = interval - elapsed
                if wait > 0:
                    time.sleep(wait)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
