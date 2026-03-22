import os
import sys
import signal
import datetime
from pathlib import Path

import toml
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False)
console = Console()

_CONFIG_DIR = Path.home() / ".screenshield"
_CONFIG_FILE = _CONFIG_DIR / "config.toml"
_PID_FILE = _CONFIG_DIR / "screenshield.pid"

_DEFAULTS = {
    "fps": 2,
    "region": {},
    "notify": True,
}


def _ensure_config():
    _CONFIG_DIR.mkdir(exist_ok=True)
    if not _CONFIG_FILE.exists():
        _CONFIG_FILE.write_text(toml.dumps(_DEFAULTS))
    return toml.loads(_CONFIG_FILE.read_text())


@app.command()
def on():
    from screenshield.core.capture import ScreenCapture
    from screenshield.core.ocr import OCRPipeline
    from screenshield.core.detector import Detector
    from screenshield.core.alert import AlertManager
    from screenshield.integrations.meetings import MeetingDetector

    cfg = _ensure_config()
    fps = cfg.get("fps", 2)
    region = cfg.get("region") or None

    ocr = OCRPipeline()
    detector = Detector()
    alert = AlertManager()
    meetings = MeetingDetector()

    _PID_FILE.write_text(str(os.getpid()))

    cap = ScreenCapture(fps=fps, region=region)

    def handle(frame):
        text = ocr.extract_text(frame)
        findings = detector.detect(text)
        if findings:
            src = meetings.active_platform() or ""
            alert.alert(findings, source_app=src)

    console.print("[green]screenshield running[/green] — press Ctrl+C to stop")
    cap.start(handle)

    try:
        signal.pause()
    except (KeyboardInterrupt, AttributeError):
        pass
    finally:
        cap.stop()
        _PID_FILE.unlink(missing_ok=True)


@app.command()
def off():
    if not _PID_FILE.exists():
        console.print("screenshield is not running")
        raise typer.Exit(1)
    pid = int(_PID_FILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        _PID_FILE.unlink(missing_ok=True)
        console.print(f"stopped (pid {pid})")
    except ProcessLookupError:
        _PID_FILE.unlink(missing_ok=True)
        console.print("process already gone")


@app.command()
def status():
    running = False
    pid = None
    if _PID_FILE.exists():
        pid = int(_PID_FILE.read_text().strip())
        try:
            os.kill(pid, 0)
            running = True
        except ProcessLookupError:
            pass

    cfg = _ensure_config()
    fps = cfg.get("fps", 2)
    state = f"[green]running[/green] (pid {pid})" if running else "[red]stopped[/red]"
    console.print(f"status   {state}")
    console.print(f"fps      {fps}")


@app.command()
def scan():
    from screenshield.core.capture import ScreenCapture
    from screenshield.core.ocr import OCRPipeline
    from screenshield.core.detector import Detector
    from screenshield.core.alert import AlertManager

    cfg = _ensure_config()
    region = cfg.get("region") or None

    cap = ScreenCapture(fps=1, region=region)
    ocr = OCRPipeline()
    detector = Detector()
    alert = AlertManager()

    frame = cap.capture_frame()
    text = ocr.extract_text(frame)
    findings = detector.detect(text)

    if findings:
        alert.alert(findings)
    else:
        console.print("[green]clean[/green] — no secrets detected")


@app.command()
def patterns():
    from screenshield.core.detector import PATTERNS

    t = Table(title="active patterns", show_header=True)
    t.add_column("name", style="bold")
    t.add_column("severity")

    severity_style = {"critical": "red", "high": "dark_orange", "medium": "yellow"}
    extras = [("credit_card", "critical"), ("env_variable", "medium")]
    all_patterns = [(name, sev) for name, sev, _ in PATTERNS] + extras

    for name, sev in all_patterns:
        t.add_row(name, f"[{severity_style.get(sev, 'white')}]{sev}[/]")

    console.print(t)


@app.command()
def stats():
    console.print("no detections yet — sqlite logging coming soon")
