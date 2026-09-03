#!/usr/bin/env python3
"""
CENTRIX Threat Intelligence CLI Entrypoint
==========================================
Usage:
  python centrix_intel.py analyse vuln --type "SQL Injection" --parameter "id"
"""
import sys
from pathlib import Path

# Ensure backend directory is on sys.path
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scanner.threat_intel.cli import main

if __name__ == "__main__":
    main()
