"""Controlled browser launcher for Centrix Manual Mode."""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class BrowserLaunchResult:
    ok: bool
    running: bool
    target_url: str = ""
    scan_id: str = ""
    profile_dir: str = ""
    proxy_server: str = ""
    mode: str = "direct"
    error: str = ""
    warning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def browser_profiles_dir() -> Path:
    configured = os.environ.get("CENTRIX_BROWSER_PROFILE_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "browser-profiles"


def proxy_server_from_status(proxy_status: dict[str, Any] | None) -> str:
    status = proxy_status or {}
    if not status.get("running"):
        return ""
    host = str(status.get("host") or "127.0.0.1")
    port = int(status.get("port") or 0)
    return f"http://{host}:{port}" if port > 0 else ""


class CentrixBrowserController:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._playwright: Any | None = None
        self._context: Any | None = None
        self._page: Any | None = None
        self._state = BrowserLaunchResult(ok=True, running=False)

    def open(self, *, target_url: str, scan_id: str = "", use_proxy: bool = True, proxy_status: dict[str, Any] | None = None) -> BrowserLaunchResult:
        with self._lock:
            self.close()
            proxy_server = proxy_server_from_status(proxy_status) if use_proxy else ""
            if use_proxy and not proxy_server:
                self._state = BrowserLaunchResult(ok=False, running=False, target_url=target_url, scan_id=scan_id, error="Manual proxy is not running.")
                return self._state
            try:
                from playwright.sync_api import sync_playwright
            except Exception as exc:
                self._state = BrowserLaunchResult(ok=False, running=False, target_url=target_url, scan_id=scan_id, error=f"Playwright is unavailable: {exc}")
                return self._state

            profile_dir = browser_profiles_dir() / (scan_id or uuid.uuid4().hex[:10])
            profile_dir.mkdir(parents=True, exist_ok=True)
            launch_options: dict[str, Any] = {"headless": False, "viewport": {"width": 1440, "height": 900}}
            if proxy_server:
                launch_options["proxy"] = {"server": proxy_server}
            warning = ""
            try:
                self._playwright = sync_playwright().start()
                self._context = self._playwright.chromium.launch_persistent_context(str(profile_dir), **launch_options)
                self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
                if target_url:
                    try:
                        self._page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                    except Exception as exc:
                        warning = f"Browser opened, but initial navigation failed: {exc}"
                self._state = BrowserLaunchResult(
                    ok=True,
                    running=True,
                    target_url=target_url,
                    scan_id=scan_id,
                    profile_dir=str(profile_dir),
                    proxy_server=proxy_server,
                    mode="http-proxy" if proxy_server else "direct",
                    warning=warning,
                )
            except Exception as exc:
                self._safe_close()
                self._state = BrowserLaunchResult(ok=False, running=False, target_url=target_url, scan_id=scan_id, profile_dir=str(profile_dir), proxy_server=proxy_server, error=str(exc))
            return self._state

    def close(self) -> BrowserLaunchResult:
        with self._lock:
            self._safe_close()
            self._state.running = False
            self._state.ok = True
            return self._state

    def status(self) -> BrowserLaunchResult:
        with self._lock:
            if self._context is None:
                self._state.running = False
            return self._state

    def _safe_close(self) -> None:
        context = self._context
        playwright = self._playwright
        self._page = None
        self._context = None
        self._playwright = None
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass
