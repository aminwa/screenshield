# Security Policy

## Reporting a vulnerability

If you find a security issue in screenshield itself, open a GitHub issue marked **[security]** or email directly. Please don't post working exploits publicly before giving a chance to patch.

## Threat model

screenshield is a local tool. The main things that can go wrong:

**Local SQLite database (`~/.screenshield/detections.db`)**
The DB stores masked values (first 4 chars + `****`) not full secrets, so a read on the file leaks pattern types and partial tokens but not complete credentials. Still, restrict permissions: `chmod 600 ~/.screenshield/detections.db`.

**Config file (`~/.screenshield/config.toml`)**
Contains no credentials, only runtime settings (FPS, region). Safe to read by any local user with file access, but don't put secrets in it.

**Screen capture**
screenshield grabs raw frames from your display. The frames are processed in memory and never written to disk. If the process is compromised while running, an attacker with local code execution already has the same screen access. The threat model assumes the machine itself is trusted.

**OCR output**
pytesseract spawns a local `tesseract` subprocess. No network activity. The text is processed in-process and not persisted.

**False negatives**
screenshield catches common patterns, not all possible secrets. Don't rely on it as your sole line of defence — use secret scanning in your VCS too.
