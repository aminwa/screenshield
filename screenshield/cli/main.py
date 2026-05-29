import os
import sys
import signal
import sqlite3
import datetime
import subprocess
from pathlib import Path

import toml
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(add_completion=False)
console = Console()

_CONFIG_DIR  = Path.home() / ".screenshield"
_CONFIG_FILE = _CONFIG_DIR / "config.toml"
_DB_FILE     = _CONFIG_DIR / "detections.db"
_PID_FILE    = _CONFIG_DIR / "screenshield.pid"
_PLIST_LABEL = "com.awlabs.screenshield"
_PLIST_PATH  = Path.home() / "Library/LaunchAgents" / f"{_PLIST_LABEL}.plist"
_LOG_FILE    = _CONFIG_DIR / "screenshield.log"

_DEFAULTS = {
    "fps": 2,
    "region": {},
    "notify": True,
    "redact": True,
}


def _ensure_config():
    _CONFIG_DIR.mkdir(exist_ok=True)
    if not _CONFIG_FILE.exists():
        _CONFIG_FILE.write_text(toml.dumps(_DEFAULTS))
    return toml.loads(_CONFIG_FILE.read_text())


def _ensure_db():
    _CONFIG_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(_DB_FILE)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS detections "
        "(id INTEGER PRIMARY KEY, timestamp TEXT, type TEXT, severity TEXT, app TEXT, masked_value TEXT)"
    )
    conn.commit()
    return conn


def _log_findings(conn, findings, app_name):
    ts = datetime.datetime.utcnow().isoformat()
    rows = [(ts, f.type, f.severity, app_name, f.matched) for f in findings]
    conn.executemany(
        "INSERT INTO detections (timestamp, type, severity, app, masked_value) VALUES (?,?,?,?,?)",
        rows,
    )
    conn.commit()


def _dedup(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.type, f.matched)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _escalate(findings, Finding):
    return [
        Finding(type=f.type, severity="critical", matched=f.matched, pattern_name=f.pattern_name)
        for f in findings
    ]


@app.command()
def start():
    """register screenshield as a background service that starts on login"""
    screenshield_bin = subprocess.run(["which", "screenshield"], capture_output=True, text=True).stdout.strip()
    if not screenshield_bin:
        console.print("[red]screenshield binary not found, is it installed?[/red]")
        raise typer.Exit(1)

    _PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    homebrew_prefix = subprocess.run(
        ["brew", "--prefix"], capture_output=True, text=True
    ).stdout.strip() or "/opt/homebrew"
    daemon_path = f"{homebrew_prefix}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{screenshield_bin}</string>
        <string>on</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{daemon_path}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{_LOG_FILE}</string>
    <key>StandardErrorPath</key>
    <string>{_LOG_FILE}</string>
</dict>
</plist>"""

    _PLIST_PATH.write_text(plist)
    subprocess.run(["launchctl", "load", str(_PLIST_PATH)], check=True)
    console.print("[green]screenshield started[/green] - running in background, starts on login")
    console.print(f"logs: {_LOG_FILE}")


@app.command()
def stop():
    """remove screenshield from background services"""
    if not _PLIST_PATH.exists():
        console.print("screenshield is not registered as a service")
        raise typer.Exit(1)
    subprocess.run(["launchctl", "unload", str(_PLIST_PATH)])
    _PLIST_PATH.unlink(missing_ok=True)
    console.print("[red]screenshield stopped[/red] - removed from login items")


@app.command()
def on(fps: int = typer.Option(0, "--fps", help="override fps from config")):
    """start monitoring in the foreground (ctrl-c to stop)"""
    from screenshield.core.capture import ScreenCapture
    from screenshield.core.ocr import OCRPipeline
    from screenshield.core.detector import Detector, Finding
    from screenshield.core.alert import AlertManager
    from screenshield.core.redact import redact_on_screen
    from screenshield.integrations.meetings import MeetingDetector
    import mss

    cfg = _ensure_config()
    fps = fps if fps > 0 else cfg.get("fps", 2)
    region = cfg.get("region") or None
    do_redact = cfg.get("redact", True)

    ocr = OCRPipeline()
    detector = Detector()
    alert = AlertManager()
    meetings = MeetingDetector()
    db = _ensure_db()

    with mss.mss() as sct:
        mon = sct.monitors[0]
        screen_w, screen_h = mon["width"], mon["height"]

    _PID_FILE.write_text(str(os.getpid()))
    cap = ScreenCapture(fps=fps, region=region)

    def handle(frame):
        platform = meetings.active_platform()
        boxes = ocr.extract_with_boxes(frame)

        text = " ".join(b["text"] for b in boxes)
        raw = detector.detect(text)
        findings = _dedup(raw)

        if not findings:
            return

        if platform:
            findings = _escalate(findings, Finding)

            if do_redact:
                secret_words = set()
                for f in findings:
                    secret_words.add(f.matched[:4].lower())

                hit_boxes = [
                    b for b in boxes
                    if any(w in b["text"].lower() for w in secret_words)
                ]
                redact_on_screen(hit_boxes or [], screen_w, screen_h, duration_ms=6000)

        alert.alert(findings, source_app=platform or "")
        _log_findings(db, findings, platform or "")

    console.print("[green]screenshield running[/green] - press Ctrl+C to stop")
    cap.start(handle)

    try:
        signal.pause()
    except (KeyboardInterrupt, AttributeError):
        pass
    finally:
        cap.stop()
        _PID_FILE.unlink(missing_ok=True)
        db.close()


@app.command()
def off():
    """stop a foreground screenshield process"""
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

    daemon = _PLIST_PATH.exists()
    cfg = _ensure_config()
    fps = cfg.get("fps", 2)

    today = datetime.date.today().isoformat()
    count = 0
    if _DB_FILE.exists():
        conn = sqlite3.connect(_DB_FILE)
        row = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE timestamp LIKE ?", (f"{today}%",)
        ).fetchone()
        conn.close()
        count = row[0] if row else 0

    state = f"[green]running[/green] (pid {pid})" if running else "[red]stopped[/red]"
    console.print(f"status      {state}")
    console.print(f"daemon      {'[green]registered[/green]' if daemon else '[dim]not registered[/dim]'}")
    console.print(f"fps         {fps}")
    console.print(f"redact      {cfg.get('redact', True)}")
    console.print(f"today       {count} detection(s)")


@app.command()
def scan():
    """single frame scan"""
    from screenshield.core.capture import ScreenCapture
    from screenshield.core.ocr import OCRPipeline
    from screenshield.core.detector import Detector, Finding
    from screenshield.core.alert import AlertManager
    from screenshield.core.redact import redact_on_screen
    from screenshield.integrations.meetings import MeetingDetector
    import mss

    cfg = _ensure_config()
    region = cfg.get("region") or None
    do_redact = cfg.get("redact", True)

    cap = ScreenCapture(fps=1, region=region)
    ocr = OCRPipeline()
    detector = Detector()
    alert = AlertManager()
    meetings = MeetingDetector()
    db = _ensure_db()

    with mss.mss() as sct:
        mon = sct.monitors[0]
        screen_w, screen_h = mon["width"], mon["height"]

    frame = cap.capture_frame()
    boxes = ocr.extract_with_boxes(frame)
    text = ocr.extract_text(frame)
    raw = detector.detect(text)
    findings = _dedup(raw)

    platform = meetings.active_platform()

    if platform and findings:
        findings = _escalate(findings, Finding)

        if do_redact:
            secret_words = {f.matched[:4].lower() for f in findings}
            hit_boxes = [b for b in boxes if any(w in b["text"].lower() for w in secret_words)]
            redact_on_screen(hit_boxes or [], screen_w, screen_h, duration_ms=6000)

    if findings:
        alert.alert(findings, source_app=platform or "")
        _log_findings(db, findings, platform or "scan")
    else:
        msg = "[green]clean[/green] - no secrets detected"
        if platform:
            msg += f" [dim]({platform} active)[/dim]"
        console.print(msg)

    db.close()


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
    if not _DB_FILE.exists():
        console.print("no detections yet")
        raise typer.Exit()

    conn = sqlite3.connect(_DB_FILE)

    by_type = conn.execute(
        "SELECT type, severity, COUNT(*) as n FROM detections GROUP BY type ORDER BY n DESC"
    ).fetchall()

    by_day = conn.execute(
        "SELECT substr(timestamp,1,10) as day, COUNT(*) as n FROM detections GROUP BY day ORDER BY day DESC LIMIT 14"
    ).fetchall()

    conn.close()

    t1 = Table(title="by pattern type")
    t1.add_column("type")
    t1.add_column("severity")
    t1.add_column("count", justify="right")
    for row in by_type:
        t1.add_row(*[str(c) for c in row])

    t2 = Table(title="by day (last 14)")
    t2.add_column("date")
    t2.add_column("count", justify="right")
    for row in by_day:
        t2.add_row(*[str(c) for c in row])

    console.print(t1)
    console.print(t2)


@app.command()
def config():
    """open the config file in $EDITOR"""
    _ensure_config()
    editor = os.environ.get("EDITOR", "nano")
    subprocess.run([editor, str(_CONFIG_FILE)])
