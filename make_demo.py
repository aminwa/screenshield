import io, json, subprocess, time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box
from pyfiglet import figlet_format

WIDTH  = 100
HEIGHT = 40

E = "\x1b"
PROMPT = f"\r\n{E}[1;32muser@demo{E}[0m:{E}[1;34m~/screenshield{E}[0m$ "

_SEVERITY_ICON = {
    "critical": ("🔴", "bold red"),
    "high":     ("🟠", "bold dark_orange"),
    "medium":   ("🟡", "bold yellow"),
}

FINDINGS = [
    {"type": "aws_access_key",        "severity": "critical", "matched": "AKIA****"},
    {"type": "github_token",           "severity": "critical", "matched": "ghp_****"},
    {"type": "db_connection_string",   "severity": "critical", "matched": "post****"},
]


def render_alert() -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=WIDTH, force_terminal=True, color_system="truecolor")
    worst = "critical"
    _, color = _SEVERITY_ICON[worst]

    logo = figlet_format("screenshield", font="slant")
    console.print()
    console.print(Text(logo, style=f"bold {color}"), justify="center")
    console.print(Rule(style=color))
    console.print(
        Text(f"  {len(FINDINGS)} secrets detected on your screen", style=f"bold {color}"),
        justify="center",
    )
    console.print()

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold white", padding=(0, 2), expand=True)
    t.add_column("",         no_wrap=True, width=2)
    t.add_column("SEVERITY", no_wrap=True, width=10)
    t.add_column("TYPE",     no_wrap=True, style="bold white")
    t.add_column("DETECTED", style="dim")

    for f in FINDINGS:
        icon, fc = _SEVERITY_ICON.get(f["severity"], ("⚪", "white"))
        t.add_row(icon, f"[{fc}]{f['severity'].upper()}[/{fc}]", f["type"], f["matched"])

    console.print(Panel(t, border_style=color, box=box.ROUNDED, padding=(1, 2)))
    console.print()

    return buf.getvalue().replace("\n", "\r\n")


def build_cast(cast_path, gif_path):
    alert = render_alert()

    def t(s, text):
        return [round(s, 3), "o", text]

    events = [
        t(0.1,  PROMPT),
        t(0.8,  "cat .env"),
        t(1.2,  "\r\n"),
        t(1.4,  f"{E}[33mAWS_ACCESS_KEY_ID{E}[0m=AKIAIOSFODNN7EXAMPLE\r\n"),
        t(1.5,  f"{E}[33mAWS_SECRET_ACCESS_KEY{E}[0m=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12\r\n"),
        t(1.6,  f"{E}[33mGITHUB_TOKEN{E}[0m=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234\r\n"),
        t(1.7,  f"{E}[33mDATABASE_URL{E}[0m=postgres://admin:s3cr3t@db.example.com/mydb\r\n"),
        t(2.1,  PROMPT),
        t(2.9,  "screenshield scan"),
        t(3.3,  "\r\n"),
        t(4.8,  alert),
        t(5.2,  PROMPT),
        t(7.5,  ""),
    ]

    header = {
        "version": 2,
        "width":   WIDTH,
        "height":  HEIGHT,
        "timestamp": int(time.time()),
        "title":   "screenshield demo",
        "env":     {"SHELL": "/bin/zsh", "TERM": "xterm-256color"},
    }

    with open(cast_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    print(f"cast written: {cast_path}")

    r = subprocess.run(
        ["agg", "--theme", "monokai", "--font-size", "14", cast_path, gif_path],
        capture_output=True, text=True,
    )
    print("gif done" if r.returncode == 0 else f"error: {r.stderr}")


if __name__ == "__main__":
    build_cast(
        "/Users/aminwafi/screenshield_demo.cast",
        "/Users/aminwafi/screenshield/demo.gif",
    )
