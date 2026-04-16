import subprocess
import sys
from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .detector import Finding

console = Console()

_SEVERITY_ICON = {
    "critical": ("🔴", "bold red"),
    "high":     ("🟠", "dark_orange"),
    "medium":   ("🟡", "yellow"),
    "low":      ("🔵", "blue"),
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


class AlertManager:
    def alert(self, findings: list[Finding], source_app: str = ""):
        if not findings:
            return

        t = Table(box=None, show_header=False, padding=(0, 2), expand=True)
        t.add_column("icon",     no_wrap=True, width=2)
        t.add_column("severity", no_wrap=True, width=10)
        t.add_column("type",     no_wrap=True, width=26)
        t.add_column("value",    style="dim")

        for f in findings:
            icon, color = _SEVERITY_ICON.get(f.severity, ("⚪", "white"))
            t.add_row(
                icon,
                f"[{color}]{f.severity.upper()}[/{color}]",
                f"[bold white]{f.type}[/bold white]",
                f.matched,
            )

        n = len(findings)
        worst = findings[0].severity if findings else "low"
        _, header_color = _SEVERITY_ICON.get(worst, ("⚪", "white"))

        subtitle = f"[dim]{source_app}[/dim]" if source_app else None
        header = f"[bold {header_color}]🛡  screenshield  ·  {n} secret{'s' if n != 1 else ''} detected[/bold {header_color}]"

        console.print()
        console.print(Panel(
            t,
            title=header,
            subtitle=subtitle,
            border_style=header_color,
            box=box.DOUBLE,
            padding=(1, 2),
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
