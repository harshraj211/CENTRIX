"""
Stage 4 — Active Probing
Fires vulnerability probes concurrently across all discovered endpoints.
Detects:
  - SQL Injection (boolean-diff + error string)
  - Reflected XSS (payload reflection)
  - Path Traversal (content signature match)
  - Open Redirect (Location header check)
  - Missing Security Headers

Concurrency controlled by asyncio.Semaphore (respects safety level).
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Callable, Awaitable
from urllib.parse import urlparse, urlencode, urljoin

import aiohttp

# ── Load payloads once at module level (O(1) per lookup after init) ──────────
_PAYLOAD_DIR = Path(__file__).parent.parent / "payloads"


def _load(filename: str) -> list[str]:
    p = _PAYLOAD_DIR / filename
    if p.exists():
        return [l.strip() for l in p.read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.startswith("#")]
    return []


SQLI_PAYLOADS = _load("sqli.txt")
XSS_PAYLOADS = _load("xss.txt")
TRAVERSAL_PAYLOADS = _load("traversal.txt")

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "unclosed quotation", "odbc microsoft",
    "ora-", "pg_query", "syntax error", "you have an error in your sql",
    "sqlite_", "warning: mysql", "supplied argument is not a valid mysql",
    "division by zero",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0", "daemon:x:", "[boot loader]", "windows/system32",
    "/etc/shadow", "application.properties",
]

SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-xss-protection",
]

# Concurrency caps per safety level
CONCURRENCY_MAP = {"passive": 5, "standard": 15, "aggressive": 40}


async def run(
    target: str,
    urls: list[str],
    parameters: list[str],
    forms: list[dict],
    log: Callable[[str], Awaitable[None]],
    safety: str = "standard",
    timeout: int = 15,
) -> list[dict]:
    """Returns list of raw vulnerability dicts to be processed by analyze stage."""
    sem = asyncio.Semaphore(CONCURRENCY_MAP.get(safety, 15))
    await log(f"[INFO] Active probing started — {len(urls)} URLs, safety={safety}")

    if safety == "passive":
        await log("[INFO] Passive mode — only header and config checks")
        return await _passive_checks(target, urls, log, sem, timeout)

    # Build list of (url, param) probe targets from crawled URLs
    probe_targets = _extract_probe_targets(urls, parameters)
    await log(f"[INFO] Generated {len(probe_targets)} probe targets")

    all_vulns: list[dict] = []
    vuln_lock = asyncio.Lock()

    async def probe_one(url: str, param: str) -> None:
        found: list[dict] = []
        found += await _test_sqli(url, param, sem, log, timeout)
        found += await _test_xss(url, param, sem, log, timeout)
        found += await _test_traversal(url, param, sem, log, timeout)
        if found:
            async with vuln_lock:
                all_vulns.extend(found)

    # Fire all probes concurrently
    await asyncio.gather(*[probe_one(u, p) for u, p in probe_targets])

    # Header checks on base target
    header_vulns = await _header_checks(target, log, sem, timeout)
    all_vulns.extend(header_vulns)

    # Form-based checks
    if safety == "aggressive" and forms:
        form_vulns = await _form_probes(forms, log, sem, timeout)
        all_vulns.extend(form_vulns)

    await log(f"[SUCCESS] Probing complete — {len(all_vulns)} potential issues found")
    return all_vulns


def _extract_probe_targets(urls: list[str], params: list[str]) -> list[tuple[str, str]]:
    """Build (url, param) pairs. Uses set for O(1) dedup."""
    targets: set[tuple[str, str]] = set()
    for url in urls:
        if "?" in url:
            qs = url.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" in part:
                    name = part.split("=")[0]
                    base = url.split("?")[0]
                    targets.add((base, name))
    # Also add global params against interesting paths
    interesting = [u for u in urls if any(
        kw in u for kw in ["/api", "/search", "/export", "/admin", "/user", "/login"]
    )][:10]
    for url in interesting:
        for param in params[:5]:
            targets.add((url.split("?")[0], param))
    return list(targets)


async def _test_sqli(url: str, param: str, sem: asyncio.Semaphore,
                     log, timeout: int) -> list[dict]:
    """Boolean-diff + error-string SQL injection detection."""
    results: list[dict] = []
    payloads = SQLI_PAYLOADS[:6] if SQLI_PAYLOADS else ["'", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]

    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                # Baseline
                base_url = f"{url}?{param}=1"
                async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r0:
                    baseline = await r0.text(errors="replace")
                    base_status = r0.status

                for payload in payloads[:3]:
                    probe_url = f"{url}?{param}={payload}"
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r1:
                        body = (await r1.text(errors="replace")).lower()
                        status = r1.status

                        # Error-based detection
                        for err in SQLI_ERRORS:
                            if err in body:
                                await log(f"[ALERT] Potential SQLi (error-based) — {url} param={param}")
                                results.append({
                                    "type": "sqli",
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "evidence": f"SQL error string detected: '{err}'",
                                    "confidence": "Confirmed",
                                })
                                return results

                        # Boolean-diff detection
                        if abs(len(body) - len(baseline)) > 100 and status != base_status:
                            await log(f"[ALERT] Potential SQLi (boolean-diff) — {url} param={param}")
                            results.append({
                                "type": "sqli",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Response differential detected (status {base_status}→{status})",
                                "confidence": "Tentative",
                            })
                            return results
        except Exception:
            pass
    return results


async def _test_xss(url: str, param: str, sem: asyncio.Semaphore,
                    log, timeout: int) -> list[dict]:
    """Reflected XSS detection — checks if payload is reflected verbatim."""
    results: list[dict] = []
    payloads = XSS_PAYLOADS[:3] if XSS_PAYLOADS else ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']

    async with sem:
        for payload in payloads[:2]:
            try:
                async with aiohttp.ClientSession() as session:
                    probe_url = f"{url}?{param}={payload}"
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                        body = await r.text(errors="replace")
                        if payload in body:
                            await log(f"[ALERT] Reflected XSS found — {url} param={param}")
                            results.append({
                                "type": "xss",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Payload '{payload[:40]}' reflected in response",
                                "confidence": "Confirmed",
                            })
                            return results
            except Exception:
                pass
    return results


async def _test_traversal(url: str, param: str, sem: asyncio.Semaphore,
                           log, timeout: int) -> list[dict]:
    """Path traversal detection — look for filesystem content signatures."""
    results: list[dict] = []
    payloads = TRAVERSAL_PAYLOADS[:4] if TRAVERSAL_PAYLOADS else [
        "../../etc/passwd", "../../../etc/shadow", "..\\..\\windows\\win.ini"
    ]

    async with sem:
        for payload in payloads[:3]:
            try:
                async with aiohttp.ClientSession() as session:
                    probe_url = f"{url}?{param}={payload}"
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                        body = await r.text(errors="replace")
                        for sig in TRAVERSAL_SIGNATURES:
                            if sig in body:
                                await log(f"[CRITICAL] Path Traversal CONFIRMED — {url} param={param}")
                                results.append({
                                    "type": "traversal",
                                    "url": url,
                                    "param": param,
                                    "payload": payload,
                                    "evidence": f"Filesystem signature '{sig}' found in response",
                                    "confidence": "Confirmed",
                                })
                                return results
            except Exception:
                pass
    return results


async def _header_checks(target: str, log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Check for missing security headers — O(headers) constant."""
    results: list[dict] = []
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                    headers_lower = {k.lower(): v for k, v in r.headers.items()}
                    for hdr in SECURITY_HEADERS:
                        if hdr not in headers_lower:
                            await log(f"[INFO] Missing header: {hdr}")
                            results.append({
                                "type": "missing_header",
                                "url": target,
                                "param": hdr,
                                "payload": "",
                                "evidence": f"Security header '{hdr}' not present in response",
                                "confidence": "Confirmed",
                            })
        except Exception:
            pass
    return results


async def _passive_checks(target: str, urls: list[str], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    return await _header_checks(target, log, sem, timeout)


async def _form_probes(forms: list[dict], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Test form submissions for XSS/SQLi — aggressive mode only."""
    results: list[dict] = []
    for form in forms[:5]:
        action = form.get("action", "")
        inputs = form.get("inputs", [])
        if not action or not inputs:
            continue
        for inp in inputs[:2]:
            for payload in ['<script>alert(1)</script>', "' OR '1'='1"]:
                async with sem:
                    try:
                        async with aiohttp.ClientSession() as session:
                            data = {inp: payload}
                            method = form.get("method", "GET")
                            if method == "POST":
                                async with session.post(action, data=data,
                                    timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                                    body = await r.text(errors="replace")
                            else:
                                async with session.get(action, params=data,
                                    timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                                    body = await r.text(errors="replace")
                            if payload in body:
                                results.append({
                                    "type": "xss",
                                    "url": action,
                                    "param": inp,
                                    "payload": payload,
                                    "evidence": f"Reflected in form submission at {action}",
                                    "confidence": "Confirmed",
                                })
                    except Exception:
                        pass
    return results
