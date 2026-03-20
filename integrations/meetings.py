import psutil


_MEETING_PROCS = {
    "zoom": "Zoom",
    "teams": "Microsoft Teams",
    "google meet": "Google Meet",
}

# browser process names that host Google Meet tabs
_BROWSERS = {"chrome", "google chrome", "firefox", "safari", "msedge", "brave browser"}


class MeetingDetector:
    def _running_names(self) -> set[str]:
        names = set()
        for proc in psutil.process_iter(["name"]):
            try:
                names.add(proc.info["name"].lower())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return names

    def is_sharing(self) -> bool:
        return self.active_platform() is not None

    def active_platform(self) -> str | None:
        names = self._running_names()

        if any("zoom" in n for n in names):
            return "Zoom"

        # Teams on mac ships as "Microsoft Teams"
        if any("teams" in n for n in names):
            return "Microsoft Teams"

        # Meet runs in-browser; we check if a browser is open and treat it as a
        # possible sharing session — caller can refine with window title if needed
        if any(b in names for b in _BROWSERS):
            return "Google Meet (browser)"

        return None
