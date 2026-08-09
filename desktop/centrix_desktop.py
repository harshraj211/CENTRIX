"""Centrix Desktop Agent scaffold.

This launcher starts the local backend and opens the web console. It is a
packaging-friendly bridge toward a future Tauri/Electron `.exe`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FRONTEND = ROOT / "FrontEnd"


def start_backend() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(BACKEND),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def start_frontend() -> subprocess.Popen | None:
    npm = "npm.cmd" if os.name == "nt" else "npm"
    if not (FRONTEND / "node_modules").exists():
        return None
    return subprocess.Popen(
        [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", "8443"],
        cwd=str(FRONTEND),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def main() -> int:
    backend = start_backend()
    frontend = start_frontend()
    time.sleep(3)
    webbrowser.open("http://127.0.0.1:8443/")
    print("Centrix Desktop Agent is running.")
    print("Console: http://127.0.0.1:8443/")
    print("Backend: http://127.0.0.1:8000/")
    print("Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(2)
            if backend.poll() is not None:
                print("Backend stopped.")
                return backend.returncode or 1
    except KeyboardInterrupt:
        pass
    finally:
        for process in (frontend, backend):
            if process and process.poll() is None:
                process.terminate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
