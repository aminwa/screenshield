#!/usr/bin/env bash
set -e

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v tesseract >/dev/null || { echo "tesseract required: brew install tesseract / apt install tesseract-ocr"; exit 1; }

PIP=$(command -v pip3 || command -v pip) && $PIP install -e .
echo "screenshield installed. run: screenshield scan"
