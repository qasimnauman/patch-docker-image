#!/usr/bin/env python3
"""Backward-compatible entrypoint for docker_vuln_patcher."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from docker_vuln_patcher.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
