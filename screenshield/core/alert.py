import subprocess
import sys
from PIL import Image
from rich.console import Console
from rich.columns import Columns
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box
from pyfiglet import figlet_format

from .detector import Finding

console = Console()

_SEVERITY_ICON = {
    "critical": ("🔴", "bold red"),
    "high":     ("🟠", "bold dark_orange"),
    "medium":   ("🟡", "bold yellow"),
    "low":      ("🔵", "bold blue"),
}


def _notify(title: str, message: str):
    try:
        if sys.platform == "darwin":
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                capture_output=True, timeout=3
            )
    except Exception:
        pass


def _header(n: int, worst: str):
    _, color = _SEVERITY_ICON.get(worst, ("⚪", "white"))

    logo = figlet_format("screenshield", font="slant")
    logo_text = Text(logo, style=f"bold {color}")

    subtitle = Text()
    subtitle.append(f"  {n} secret{'s' if n != 1 else ''} detected on your screen", style=f"bold {color}")

    console.print()
    console.print(logo_text, justify="center")
    console.print(Rule(style=color))
    console.print(subtitle, justify="center")
    console.print()


class AlertManager:
    def alert(self, findings: list[Finding], source_app: str = ""):
        if not findings:
            return

        worst = findings[0].severity

        _header(len(findings), worst)

        t = Table(box=box.SIMPLE, show_header=True, header_style="bold white", padding=(0, 2), expand=True)
        t.add_column("",         no_wrap=True, width=2)
        t.add_column("SEVERITY", no_wrap=True, width=10)
        t.add_column("TYPE",     no_wrap=True, style="bold white")
        t.add_column("DETECTED", style="dim")

        for f in findings:
            icon, color = _SEVERITY_ICON.get(f.severity, ("⚪", "white"))
            t.add_row(
                icon,
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.type,
                f.matched,
            )

        _, color = _SEVERITY_ICON.get(worst, ("⚪", "white"))

        footer = ""
        if source_app:
            footer = f"[dim]detected via[/dim] [bold]{source_app}[/bold]"

        console.print(Panel(
            t,
            border_style=color,
            box=box.ROUNDED,
            padding=(1, 2),
            subtitle=footer or None,
        ))
        console.print()

        types = ", ".join(sorted({f.type for f in findings}))
        _notify("screenshield: secret detected", types)

    def blur_region(self, image: Image.Image, x: int, y: int, w: int, h: int) -> Image.Image:
        img = image.copy()
        region = img.crop((x, y, x + w, y + h))
        # pixelate by downscale then upscale — harder blur than gaussian for credentials
        small = region.resize((max(1, w // 8), max(1, h // 8)), Image.BOX)
        pixelated = small.resize((w, h), Image.NEAREST)
        img.paste(pixelated, (x, y))
        return img
