import subprocess
import sys
from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .detector import Finding

console = Console()

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
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

        body = Text()
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            body.append(f"  {f.type:<28}", style="bold white")
            body.append(f" {f.matched}\n", style="dim")

        title = "screenshield" + (f"  —  {source_app}" if source_app else "")
        console.print(Panel(body, title=f"[bold red]{title}[/bold red]", border_style="red"))

        types = ", ".join(sorted({f.type for f in findings}))
        _notify("screenshield: secret detected", types)

    def blur_region(self, image: Image.Image, x: int, y: int, w: int, h: int) -> Image.Image:
        img = image.copy()
        region = img.crop((x, y, x + w, y + h))
        # pixelate by downscale then upscale — blurs harder than gaussian for credentials
        small = region.resize((max(1, w // 8), max(1, h // 8)), Image.BOX)
        pixelated = small.resize((w, h), Image.NEAREST)
        img.paste(pixelated, (x, y))
        return img
