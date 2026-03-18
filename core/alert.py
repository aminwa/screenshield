from PIL import Image, ImageFilter
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

try:
    from plyer import notification as _plyer_notify
    _PLYER = True
except Exception:
    _PLYER = False

from .detector import Finding

console = Console()

_SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "dark_orange",
    "medium": "yellow",
}


class AlertManager:
    def alert(self, findings: list[Finding], source_app: str = ""):
        if not findings:
            return

        body = Text()
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            label = f"[{color}][{f.severity.upper()}][/{color}]"
            body.append(f"  {f.type:<28}", style="bold white")
            body.append(f" {f.matched}\n", style="dim")

        title = "screenshield" + (f"  —  {source_app}" if source_app else "")
        console.print(Panel(body, title=f"[bold red]{title}[/bold red]", border_style="red"))

        if _PLYER:
            types = ", ".join(sorted({f.type for f in findings}))
            try:
                _plyer_notify.notify(
                    title="screenshield: secret detected",
                    message=types,
                    timeout=5,
                )
            except Exception:
                pass

    def blur_region(self, image: Image.Image, x: int, y: int, w: int, h: int) -> Image.Image:
        img = image.copy()
        region = img.crop((x, y, x + w, y + h))
        # pixelate by downscale then upscale — blurs harder than gaussian for credentials
        small = region.resize((max(1, w // 8), max(1, h // 8)), Image.BOX)
        pixelated = small.resize((w, h), Image.NEAREST)
        img.paste(pixelated, (x, y))
        return img
