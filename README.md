<div align="center">

# screenshield

**Local screen guardian. Detects secrets before you share them.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-15%20passing-brightgreen)](#)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#)

*Real-time OCR · 12 secret types · meeting detection · zero cloud*

</div>

---

```
╔══════════════════════════════════════════════════════════════╗
║  🛡  screenshield  —  SECRET DETECTED                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  🔴  CRITICAL   private_key                                  ║
║      -----BEGIN RSA PRIVATE****                              ║
║                                                              ║
║  🟠  HIGH       github_token                                 ║
║      ghp_Kx9a****                                            ║
║                                                              ║
║  🟡  MEDIUM     env_variable                                 ║
║      DATABASE_URL=****                                       ║
║                                                              ║
║  3 finding(s) · Zoom screen share active · stop sharing     ║
╚══════════════════════════════════════════════════════════════╝
```

---

## What it does

screenshield watches your screen continuously. Every 2 seconds it captures a frame, runs OCR, and scans the text for secrets. If anything is found while you are in a meeting or screen share, it fires a critical alert immediately.

| Feature | Detail |
|---------|--------|
| **Real-time capture** | `mss` grabs frames at 2+ FPS with negligible CPU overhead |
| **Local OCR** | Tesseract with preprocessing tuned for terminal fonts and dark themes |
| **12 secret types** | AWS, GCP, Azure, GitHub, JWTs, private keys, DB strings, SSNs, credit cards and more |
| **Meeting detection** | Detects active Zoom, Teams, or Google Meet and escalates alert severity |
| **Entropy filtering** | Shannon entropy scoring cuts false positives on env variable values |
| **Zero cloud** | All processing on-device — no telemetry, no accounts, no internet after install |

---

## Install

**Requirements:** Python 3.10+, [Tesseract](https://github.com/tesseract-ocr/tesseract)

```bash
# macOS
brew install tesseract

# Ubuntu / Debian
sudo apt install tesseract-ocr
```

```bash
git clone https://github.com/aminwa/screenshield.git
cd screenshield
bash install.sh
```

Or manually:

```bash
pip install -e .
```

---

## Quick start

```bash
# single scan — see what screenshield finds right now
screenshield scan

# start continuous monitoring (Ctrl-C to stop)
screenshield on

# check whether screenshield is running
screenshield status

# list all active detection patterns
screenshield patterns

# view detection history
screenshield stats

# open config in $EDITOR
screenshield config
```

---

## Detection patterns

| Pattern | Severity | Example |
|---------|----------|---------|
| `aws_access_key` | 🟠 High | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | 🔴 Critical | `aws_secret = wJalrXUtn...` |
| `gcp_api_key` | 🟠 High | `AIzaSyD-...` |
| `github_token` | 🟠 High | `ghp_Kx9aZ...` |
| `private_key` | 🔴 Critical | `-----BEGIN RSA PRIVATE KEY-----` |
| `jwt_token` | 🟠 High | `eyJhbGci...` |
| `bearer_token` | 🟠 High | `Authorization: Bearer abc...` |
| `db_connection_string` | 🟠 High | `postgres://user:pass@host/db` |
| `azure_key` | 🟠 High | Azure storage / subscription key |
| `env_variable` | 🟡 Medium | `SECRET_KEY=xK9d...` (entropy ≥ 3.5 bits) |
| `credit_card` | 🔴 Critical | 13–19 digit sequence, Luhn-validated |
| `ssn` | 🔴 Critical | `123-45-6789` |

Matched values are always **masked** in output — first 4 characters shown, rest replaced with `****`.

---

## Meeting detection

screenshield monitors running processes and escalates all findings to `CRITICAL` when a screen share is active.

| Platform | How it detects |
|----------|----------------|
| Zoom | `zoom.us` process |
| Microsoft Teams | `teams` process |
| Google Meet | Browser process heuristic |

---

## Privacy

Nothing leaves your machine — ever.

| Data | Leaves device? |
|------|----------------|
| Screen frames | ✗ Processed in-memory, never written to disk |
| OCR text | ✗ Stays in-process |
| Matched secrets | ✗ Masked immediately, stored locally in SQLite |
| Detection history | ✗ Local only — `~/.screenshield/detections.db` |
| Network calls | ✗ None — there is no outbound connection |

The local SQLite log stores only: timestamp, secret type, severity, and the masked value. The raw matched string is never persisted.

---

## Configuration

Config lives at `~/.screenshield/config.toml`, created on first run.

```toml
[capture]
fps    = 2
region = "full"   # or { top = 0, left = 0, width = 1920, height = 1080 }

[detection]
min_severity  = "medium"   # low | medium | high | critical
entropy_floor = 3.5        # minimum Shannon entropy for env_variable matches

[alerts]
terminal      = true    # rich banner in terminal
system        = true    # OS notification via plyer
blur_overlay  = false   # experimental: blur detected regions on a preview window

[meetings]
enabled = true
```

---

## How it works

```
screen frame (mss)
      │
      ▼
 preprocessing        grayscale → adaptive threshold → sharpen
      │
      ▼
   tesseract           plain text per frame
      │
      ▼
   detector            regex + entropy → list of findings
      │
      ▼
 meeting check         psutil process scan
      │
      ▼
    alert              rich terminal banner + OS notification
      │
      ▼
  sqlite log           ~/.screenshield/detections.db
```

---

## Project structure

```
screenshield/
├── core/
│   ├── capture.py       # mss screen capture, threaded loop
│   ├── ocr.py           # tesseract wrapper + preprocessing
│   ├── detector.py      # regex + entropy engine, Luhn check
│   └── alert.py         # rich banner + plyer + blur overlay
├── integrations/
│   └── meetings.py      # zoom / teams / meet detection via psutil
├── cli/
│   └── main.py          # typer CLI — on / off / status / scan / patterns / stats / config
└── tests/
    ├── test_detector.py  # one test per pattern type
    ├── test_ocr.py
    └── test_meetings.py
```

---

## Running tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Built by

**AW Labs** — tools that make developers faster.

> "Privacy-first, local-first, fast."

---

## License

MIT © AW Labs
