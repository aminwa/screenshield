# screenshield

A local, real-time screen guardian that captures your display, runs OCR, and alerts you the moment credentials or sensitive data appear on screen — before you share your screen or after a paste you're not sure about.

## Why

Screen-sharing accidents are one of the most common ways secrets leak. You paste a `.env` file into the wrong window, scroll past a terminal with tokens, or share your screen in a meeting with credentials still visible. screenshield catches those moments locally, in real time, with no data leaving your machine.

## Requirements

- Python 3.10+
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)

```
# macOS
brew install tesseract

# Ubuntu/Debian
apt install tesseract-ocr
```

## Install

```bash
git clone https://github.com/aminwa/screenshield
cd screenshield
bash install.sh
```

## Usage

```bash
# start the monitor (runs in foreground, Ctrl+C to stop)
screenshield on

# stop a background screenshield process
screenshield off

# show running status, FPS, and today's detection count
screenshield status

# single-frame scan — useful for quick checks
screenshield scan

# list all active detection patterns
screenshield patterns

# rich table of historical detections from local SQLite
screenshield stats
```

Config lives at `~/.screenshield/config.toml` and is created on first run. Adjust `fps` and `region` there.

## Pattern reference

| Pattern | Severity |
|---|---|
| `aws_access_key` | high |
| `aws_secret_key` | critical |
| `gcp_api_key` | high |
| `github_token` | high |
| `private_key` | critical |
| `jwt_token` | high |
| `bearer_token` | high |
| `db_connection_string` | high |
| `env_variable` | medium |
| `credit_card` | critical |
| `ssn` | critical |
| `azure_key` | high |

Credit card detection uses a Luhn check on top of the regex — false positive rate is very low. Environment variable detection uses Shannon entropy to filter out low-value matches like `PORT=8080`.

## Privacy

Nothing leaves your machine. OCR runs locally via Tesseract. Detections are stored in a local SQLite database at `~/.screenshield/detections.db`. No telemetry, no network calls, no cloud.
