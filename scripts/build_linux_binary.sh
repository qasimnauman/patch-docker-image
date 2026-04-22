#!/usr/bin/env bash
set -euo pipefail

# Linux-focused binary packaging helper.
python -m pip install --upgrade pip
python -m pip install pyinstaller

pyinstaller \
  --onefile \
  --name docker-vuln-patcher \
  patch_image.py

echo "Binary created at: dist/docker-vuln-patcher"
