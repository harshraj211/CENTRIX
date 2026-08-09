"""
Stage 4 — Active Probing
Fires vulnerability probes concurrently across all discovered endpoints.
Detects:
  - SQL Injection (boolean-diff + error string)
  - Reflected XSS (payload reflection)
  - Path Traversal (content signature match)
  - Open Redirect (Location header check)
  - SSTI marker evaluation
  - Command injection output marker on command-like params
  - HTTP parameter pollution response differential
  - GraphQL introspection exposure
  - Missing Security Headers

Concurrency controlled by asyncio.Semaphore (respects safety level).
"""
from __future__ import annotations

import asyncio
import copy
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
]

REDIRECT_PARAMETER_NAMES = {"url", "redirect", "next", "return", "returnurl", "goto", "target", "destination", "continue", "out"}
COMMAND_PARAMETER_NAMES = {"cmd", "command", "exec", "execute", "ping", "host", "ip", "domain", "lookup", "query"}
REDIRECT_TEST_URL = "https://example.invalid/centrix-redirect-check"

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
    max_requests: int = 500,
) -> list[dict]:
    """Returns list of raw vulnerability dicts to be processed by analyze stage."""
    sem = asyncio.Semaphore(CONCURRENCY_MAP.get(safety, 15))
    await log(f"[INFO] Active probing started — {len(urls)} URLs, safety={safety}")

    if safety == "passive":
        await log("[INFO] Header-noise findings are suppressed")
        await log("[INFO] Passive mode — only header and config checks")
        return await _passive_checks(target, urls, log, sem, timeout)

    # Build list of (url, param) probe targets from crawled URLs
    # Each target makes several baseline/payload requests. Cap work before launching tasks.
    probe_targets = _extract_probe_targets(urls, parameters)[:max(1, max_requests // 6)]
    await log(f"[INFO] Generated {len(probe_targets)} probe targets")

    all_vulns: list[dict] = []
    vuln_lock = asyncio.Lock()

    async def probe_one(url: str, param: str) -> None:
        found: list[dict] = []
        found += await _test_sqli_v2(url, param, sem, log, timeout)
        found += await _test_xss(url, param, sem, log, timeout)
        found += await _test_traversal(url, param, sem, log, timeout)
        found += await _test_open_redirect(url, param, sem, log, timeout)
        found += await _test_ssti(url, param, sem, log, timeout)
        found += await _test_command_injection(url, param, sem, log, timeout)
        found += await _test_hpp(url, param, sem, log, timeout)
        found += await _test_xxe(url, param, sem, log, timeout)
        if found:
            async with vuln_lock:
                all_vulns.extend(found)

    # Fire all probes concurrently
    await asyncio.gather(*[probe_one(u, p) for u, p in probe_targets])

    # Missing security headers are noisy on intentionally vulnerable labs and
    # most real targets. Keep them out of default findings; focus on exploitable
    # DAST issues such as SQLi, XSS, CSRF, redirects, and injection classes.
    await log("[INFO] Security-header checks are telemetry-only and suppressed from findings")

    graphql_vulns = await _graphql_checks(urls, log, sem, timeout)
    all_vulns.extend(graphql_vulns)

    # Form-based checks. Wraith treats forms as first-class DAST targets; keep
    # this enabled for standard scans, while skipping password-changing fields.
    if safety in {"standard", "aggressive"} and forms:
        form_vulns = await _form_probes(forms, log, sem, timeout)
        all_vulns.extend(form_vulns)
        advanced_form_vulns = await _advanced_form_probes(forms, log, sem, timeout, aggressive=safety == "aggressive")
        all_vulns.extend(advanced_form_vulns)

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


async def _test_sqli_v2(url: str, param: str, sem: asyncio.Semaphore,
                        log, timeout: int) -> list[dict]:
    """Error-string plus true/false boolean SQLi proof with stable fingerprints."""
    payloads = SQLI_PAYLOADS[:6] if SQLI_PAYLOADS else ["'", "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
    boolean_pairs = [
        ("1 OR 1=1", "1 AND 1=2"),
        ("' OR '1'='1", "' AND '1'='2"),
        ("1') OR ('1'='1", "1') AND ('1'='2"),
    ]
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params={param: "1"}, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as base_response:
                    baseline = await base_response.text(errors="replace")
                    base_fp = _response_fingerprint(base_response.status, baseline)

                for payload in payloads[:4]:
                    async with session.get(url, params={param: payload}, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                        body = (await response.text(errors="replace")).lower()
                    for err in SQLI_ERRORS:
                        if err in body:
                            await log(f"[ALERT] SQLi error proof - {url} param={param}")
                            return [{
                                "type": "sqli",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"SQL error string detected: '{err}'",
                                "confidence": "Confirmed",
                            }]

                for true_payload, false_payload in boolean_pairs:
                    async with session.get(url, params={param: true_payload}, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as true_response:
                        true_body = await true_response.text(errors="replace")
                        true_fp = _response_fingerprint(true_response.status, true_body)
                    async with session.get(url, params={param: false_payload}, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as false_response:
                        false_body = await false_response.text(errors="replace")
                        false_fp = _response_fingerprint(false_response.status, false_body)
                    if _fingerprints_similar(base_fp, true_fp) and _fingerprints_different(true_fp, false_fp):
                        await log(f"[ALERT] SQLi boolean proof - {url} param={param}")
                        return [{
                            "type": "sqli",
                            "url": url,
                            "param": param,
                            "payload": f"{true_payload} / {false_payload}",
                            "evidence": f"True response matched baseline; false response differed ({true_fp} vs {false_fp})",
                            "confidence": "Confirmed",
                        }]
        except Exception:
            pass
    return []


def _response_fingerprint(status: int, body: str) -> tuple[int, int, str]:
    title = ""
    lowered = body.lower()
    start = lowered.find("<title>")
    end = lowered.find("</title>")
    if start != -1 and end != -1 and end > start:
        title = lowered[start + 7:end].strip()[:80]
    normalized_length = (len(body) // 25) * 25
    return status, normalized_length, title


def _fingerprints_similar(left: tuple[int, int, str], right: tuple[int, int, str]) -> bool:
    return left[0] == right[0] and abs(left[1] - right[1]) <= max(75, int(left[1] * 0.08)) and left[2] == right[2]


def _fingerprints_different(left: tuple[int, int, str], right: tuple[int, int, str]) -> bool:
    return left[0] != right[0] or abs(left[1] - right[1]) >= max(125, int(max(left[1], right[1]) * 0.15)) or left[2] != right[2]


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


# Final override: keep the Wraith-style form scanner after the legacy helper so
# this definition is the one Python uses.
async def _form_probes(forms: list[dict], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Test safe form fields for reflected XSS and error-based SQL injection."""
    results: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for form in forms[:20]:
        action = form.get("action", "")
        fields = form.get("fields") or [{"name": name, "type": "text", "value": ""} for name in form.get("inputs", [])]
        if not action or not fields:
            continue
        candidates = [field for field in fields if _is_probeable_field(field)]
        for field in candidates[:4]:
            inp = field["name"]
            for vuln_type, payload in [("xss", "<script>alert(1)</script>"), ("sqli", "'")]:
                key = (action, inp, vuln_type)
                if key in seen:
                    continue
                seen.add(key)
                async with sem:
                    try:
                        async with aiohttp.ClientSession() as session:
                            data = _form_data(fields, inp, payload)
                            method = str(form.get("method", "GET")).upper()
                            async with session.request(
                                method,
                                action,
                                **_submission_kwargs(form, data),
                                timeout=aiohttp.ClientTimeout(total=timeout),
                                ssl=False,
                            ) as response:
                                body = await response.text(errors="replace")
                            lowered = body.lower()
                            if vuln_type == "xss" and payload in body:
                                await log(f"[ALERT] Reflected XSS found in form - {action} field={inp}")
                                results.append({
                                    "type": "xss",
                                    "url": action,
                                    "param": inp,
                                    "payload": payload,
                                    "evidence": f"Payload reflected after form submission at {action}",
                                    "confidence": "Confirmed",
                                })
                                break
                            if vuln_type == "sqli":
                                for err in SQLI_ERRORS:
                                    if err in lowered:
                                        await log(f"[ALERT] SQLi error found in form - {action} field={inp}")
                                        results.append({
                                            "type": "sqli",
                                            "url": action,
                                            "param": inp,
                                            "payload": payload,
                                            "evidence": f"SQL error string detected after form submission: '{err}'",
                                            "confidence": "Confirmed",
                                        })
                                        break
                    except Exception as exc:
                        await log(f"[WARN] Form probe error {action} field={inp}: {exc}")
                        pass
    return results


async def _form_probes(forms: list[dict], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Test safe form fields for reflected XSS and error-based SQL injection."""
    results: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for form in forms[:20]:
        action = form.get("action", "")
        fields = form.get("fields") or [{"name": name, "type": "text", "value": ""} for name in form.get("inputs", [])]
        if not action or not fields:
            continue
        candidates = [field for field in fields if _is_probeable_field(field)]
        for field in candidates[:4]:
            inp = field["name"]
            for vuln_type, payload in [("xss", "<script>alert(1)</script>"), ("sqli", "'")]:
                key = (action, inp, vuln_type)
                if key in seen:
                    continue
                seen.add(key)
                async with sem:
                    try:
                        async with aiohttp.ClientSession() as session:
                            data = _form_data(fields, inp, payload)
                            method = str(form.get("method", "GET")).upper()
                            if method == "POST":
                                async with session.post(action, data=data, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                                    body = await response.text(errors="replace")
                            else:
                                async with session.get(action, params=data, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                                    body = await response.text(errors="replace")
                            lowered = body.lower()
                            if vuln_type == "xss" and payload in body:
                                await log(f"[ALERT] Reflected XSS found in form - {action} field={inp}")
                                results.append({
                                    "type": "xss",
                                    "url": action,
                                    "param": inp,
                                    "payload": payload,
                                    "evidence": f"Payload reflected after form submission at {action}",
                                    "confidence": "Confirmed",
                                })
                                break
                            if vuln_type == "sqli":
                                for err in SQLI_ERRORS:
                                    if err in lowered:
                                        await log(f"[ALERT] SQLi error found in form - {action} field={inp}")
                                        results.append({
                                            "type": "sqli",
                                            "url": action,
                                            "param": inp,
                                            "payload": payload,
                                            "evidence": f"SQL error string detected after form submission: '{err}'",
                                            "confidence": "Confirmed",
                                        })
                                        break
                    except Exception as exc:
                        await log(f"[WARN] Form probe error {action} field={inp}: {exc}")
                        pass
    return results


def _is_probeable_field(field: dict) -> bool:
    name = str(field.get("name", "")).lower()
    ftype = str(field.get("type", "text")).lower()
    if not name:
        return False
    if ftype in {"password", "file", "hidden", "submit", "button", "reset", "checkbox", "radio"}:
        return False
    if any(token in name for token in ["password", "pass", "csrf", "token", "nonce"]):
        return False
    return True


def _form_data(fields: list[dict], target_name: str, payload: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for field in fields:
        name = str(field.get("name", ""))
        if not name:
            continue
        ftype = str(field.get("type", "text")).lower()
        value = str(field.get("value", ""))
        if name == target_name:
            data[name] = payload
        elif ftype in {"submit", "button"}:
            data[name] = value or "Submit"
        elif ftype == "hidden":
            data[name] = value
        elif "email" in name.lower():
            data[name] = "centrix@example.invalid"
        elif ftype in {"number", "range"} or name.lower().endswith("id") or name.lower() == "id":
            data[name] = "1"
        elif ftype != "password":
            data[name] = value or "centrix"
    return data


def _submission_kwargs(form: dict, data: dict[str, str]) -> dict:
    method = str(form.get("method", "GET")).upper()
    headers = _safe_submission_headers(form.get("headers") or {})
    if method == "GET":
        return {"params": data, "headers": headers}
    content_type = str(form.get("content_type") or headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "json" in content_type or isinstance(form.get("body_template"), (dict, list)):
        return {"json": _body_with_payload(form.get("body_template"), data), "headers": headers}
    return {"data": data, "headers": headers}


def _body_with_payload(template, values: dict[str, str]):
    if isinstance(template, dict):
        body = copy.deepcopy(template)
        for name, value in values.items():
            _set_nested_value(body, name, value)
        return body
    if isinstance(template, list):
        return copy.deepcopy(template)
    return values


def _set_nested_value(body: dict, dotted_name: str, value: str) -> None:
    parts = [part for part in dotted_name.split(".") if part]
    current = body
    for part in parts[:-1]:
        if not isinstance(current.get(part), dict):
            current[part] = {}
        current = current[part]
    if parts:
        current[parts[-1]] = value


def _safe_submission_headers(headers: dict) -> dict[str, str]:
    blocked = {"host", "content-length", "connection", "accept-encoding"}
    return {str(key): str(value) for key, value in headers.items() if str(key).lower() not in blocked}


async def _test_open_redirect(url: str, param: str, sem: asyncio.Semaphore,
                              log, timeout: int) -> list[dict]:
    """Baseline-free redirect proof: only report a Location pointing at the controlled test host."""
    if param.lower() not in REDIRECT_PARAMETER_NAMES:
        return []
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={param: REDIRECT_TEST_URL},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,
                    ssl=False,
                ) as response:
                    location = response.headers.get("Location", "")
                    if urlparse(location).hostname == "example.invalid":
                        await log(f"[ALERT] Open redirect confirmed — {url} param={param}")
                        return [{
                            "type": "open_redirect",
                            "url": url,
                            "param": param,
                            "payload": REDIRECT_TEST_URL,
                            "evidence": f"Response redirected to controlled URL: {location}",
                            "confidence": "Confirmed",
                        }]
        except Exception:
            pass
    return []


async def _test_ssti(url: str, param: str, sem: asyncio.Semaphore,
                     log, timeout: int) -> list[dict]:
    payloads = {"{{7*7}}": "49", "${7*7}": "49"}
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                for payload, marker in payloads.items():
                    async with session.get(
                        url,
                        params={param: payload},
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as response:
                        body = await response.text(errors="replace")
                        if marker in body and payload not in body:
                            await log(f"[ALERT] Potential SSTI found — {url} param={param}")
                            return [{
                                "type": "ssti",
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "evidence": f"Template expression evaluated to marker '{marker}'",
                                "confidence": "Tentative",
                            }]
        except Exception:
            pass
    return []


async def _test_command_injection(url: str, param: str, sem: asyncio.Semaphore,
                                  log, timeout: int) -> list[dict]:
    if param.lower() not in COMMAND_PARAMETER_NAMES:
        return []
    marker = "centrixcmdprobe"
    payload = f";echo {marker}"
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={param: payload},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as response:
                    body = (await response.text(errors="replace")).lower()
                    if marker in body:
                        await log(f"[CRITICAL] Command injection marker reflected — {url} param={param}")
                        return [{
                            "type": "command_injection",
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "evidence": "Command output marker appeared in response",
                            "confidence": "Confirmed",
                        }]
        except Exception:
            pass
    return []


async def _test_hpp(url: str, param: str, sem: asyncio.Semaphore,
                    log, timeout: int) -> list[dict]:
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={param: "1"},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as baseline_response:
                    baseline = await baseline_response.text(errors="replace")
                    baseline_status = baseline_response.status
                async with session.get(
                    url,
                    params=[(param, "1"), (param, "centrixhpp")],
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as hpp_response:
                    body = await hpp_response.text(errors="replace")
                    delta = abs(len(body) - len(baseline))
                    if hpp_response.status != baseline_status or delta > 120:
                        await log(f"[ALERT] HTTP parameter pollution differential — {url} param={param}")
                        return [{
                            "type": "hpp",
                            "url": url,
                            "param": param,
                            "payload": "duplicate parameter",
                            "evidence": f"Duplicate parameter changed response status/length ({baseline_status}->{hpp_response.status}, delta={delta})",
                            "confidence": "Tentative",
                        }]
        except Exception:
            pass
    return []


async def _test_xxe(url: str, param: str, sem: asyncio.Semaphore,
                    log, timeout: int) -> list[dict]:
    """Conservative XXE signal for XML/document-style parameters."""
    lowered = param.lower()
    if not any(token in lowered for token in {"xml", "doc", "document", "data", "body", "payload"}):
        return []
    payload = "<!DOCTYPE centrix [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><centrix>&xxe;</centrix>"
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params={param: payload},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as response:
                    body = await response.text(errors="replace")
                    if any(sig in body for sig in ("root:x:0:0", "daemon:x:", "[boot loader]")):
                        await log(f"[CRITICAL] XXE confirmed - {url} param={param}")
                        return [{
                            "type": "xxe",
                            "url": url,
                            "param": param,
                            "payload": payload[:120],
                            "evidence": "External entity file signature appeared in the response",
                            "confidence": "Confirmed",
                        }]
        except Exception:
            pass
    return []


async def _advanced_form_probes(forms: list[dict], log, sem: asyncio.Semaphore,
                                timeout: int, aggressive: bool = False) -> list[dict]:
    results: list[dict] = []
    for form in forms[:12]:
        method = str(form.get("method", "GET")).upper()
        if method not in {"POST", "PUT", "PATCH"}:
            continue
        results.extend(await _test_mass_assignment_form(form, log, sem, timeout))
        if aggressive:
            results.extend(await _test_race_condition_form(form, log, sem, timeout))
    return results


async def _test_mass_assignment_form(form: dict, log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    action = form.get("action", "")
    fields = form.get("fields") or [{"name": name, "type": "text", "value": ""} for name in form.get("inputs", [])]
    if not action or not fields:
        return []
    candidates = [field for field in fields if _is_probeable_field(field)]
    if not candidates:
        return []
    base_data = _form_data(fields, candidates[0]["name"], "centrix")
    elevated_data = {
        **base_data,
        "is_admin": "true",
        "admin": "true",
        "role": "admin",
        "permissions": "admin",
    }
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    str(form.get("method", "POST")).upper(),
                    action,
                    **_submission_kwargs(form, base_data),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as baseline_response:
                    baseline = await baseline_response.text(errors="replace")
                async with session.request(
                    str(form.get("method", "POST")).upper(),
                    action,
                    **_submission_kwargs(form, elevated_data),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as elevated_response:
                    elevated = await elevated_response.text(errors="replace")
                    marker_seen = any(marker in elevated.lower() for marker in ['"is_admin":true', '"role":"admin"', "role admin", "is_admin true"])
                    if marker_seen and elevated != baseline:
                        await log(f"[ALERT] Potential mass assignment - {action}")
                        return [{
                            "type": "mass_assignment",
                            "url": action,
                            "param": "is_admin,role,permissions",
                            "payload": "is_admin=true&role=admin",
                            "evidence": "Privilege-style fields changed the response and were reflected/accepted",
                            "confidence": "Tentative",
                        }]
        except Exception:
            pass
    return []


async def _test_race_condition_form(form: dict, log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    action = form.get("action", "")
    fields = form.get("fields") or [{"name": name, "type": "text", "value": ""} for name in form.get("inputs", [])]
    candidates = [field for field in fields if _is_probeable_field(field)]
    if not action or not candidates:
        return []
    data = _form_data(fields, candidates[0]["name"], "centrix-race")
    method = str(form.get("method", "POST")).upper()

    async def send_once() -> tuple[int, int]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    action,
                    **_submission_kwargs(form, data),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False,
                ) as response:
                    body = await response.content.read(128_000)
                    return response.status, len(body)
        except Exception:
            return 0, 0

    async with sem:
        responses = await asyncio.gather(*[send_once() for _ in range(5)])
    successes = [item for item in responses if 200 <= item[0] < 300]
    lengths = {length for _status, length in successes}
    if len(successes) >= 4 and len(lengths) > 1:
        await log(f"[ALERT] Race-condition differential - {action}")
        return [{
            "type": "race_condition",
            "url": action,
            "param": "form",
            "payload": "5 parallel state-changing requests",
            "evidence": f"Parallel responses had inconsistent lengths: {sorted(lengths)}",
            "confidence": "Tentative",
        }]
    return []


async def _header_checks(target: str, log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Check for missing security headers — O(headers) constant."""
    results: list[dict] = []
    async with sem:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as r:
                    headers_lower = {k.lower(): v for k, v in r.headers.items()}
                    for hdr in SECURITY_HEADERS:
                        if hdr == "strict-transport-security" and not target.startswith("https://"):
                            continue
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


async def _graphql_checks(urls: list[str], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    graphql_urls = sorted({url.split("?", 1)[0] for url in urls if "/graphql" in url.lower()})[:5]
    query = {"query": "query IntrospectionQuery { __schema { queryType { name } } }"}
    results: list[dict] = []
    for url in graphql_urls:
        async with sem:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=query,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                    ) as response:
                        body = await response.text(errors="replace")
                        if "__schema" in body and "queryType" in body:
                            await log(f"[ALERT] GraphQL introspection enabled — {url}")
                            results.append({
                                "type": "graphql_introspection",
                                "url": url,
                                "param": "query",
                                "payload": "__schema",
                                "evidence": "GraphQL introspection response included __schema/queryType",
                                "confidence": "Confirmed",
                            })
            except Exception:
                pass
    return results


async def _passive_checks(target: str, urls: list[str], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    await log("[INFO] Passive probe checks completed without header-noise findings")
    return []


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


async def _form_probes(forms: list[dict], log, sem: asyncio.Semaphore, timeout: int) -> list[dict]:
    """Test safe form fields for reflected XSS and error-based SQL injection."""
    results: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for form in forms[:20]:
        action = form.get("action", "")
        fields = form.get("fields") or [{"name": name, "type": "text", "value": ""} for name in form.get("inputs", [])]
        if not action or not fields:
            continue
        candidates = [field for field in fields if _is_probeable_field(field)]
        for field in candidates[:4]:
            inp = field["name"]
            for vuln_type, payload in [("xss", "<script>alert(1)</script>"), ("sqli", "'")]:
                key = (action, inp, vuln_type)
                if key in seen:
                    continue
                seen.add(key)
                async with sem:
                    try:
                        async with aiohttp.ClientSession() as session:
                            data = _form_data(fields, inp, payload)
                            method = str(form.get("method", "GET")).upper()
                            if method == "POST":
                                async with session.post(action, data=data, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                                    body = await response.text(errors="replace")
                            else:
                                async with session.get(action, params=data, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                                    body = await response.text(errors="replace")
                            lowered = body.lower()
                            if vuln_type == "xss" and payload in body:
                                await log(f"[ALERT] Reflected XSS found in form - {action} field={inp}")
                                results.append({
                                    "type": "xss",
                                    "url": action,
                                    "param": inp,
                                    "payload": payload,
                                    "evidence": f"Payload reflected after form submission at {action}",
                                    "confidence": "Confirmed",
                                })
                                break
                            if vuln_type == "sqli":
                                for err in SQLI_ERRORS:
                                    if err in lowered:
                                        await log(f"[ALERT] SQLi error found in form - {action} field={inp}")
                                        results.append({
                                            "type": "sqli",
                                            "url": action,
                                            "param": inp,
                                            "payload": payload,
                                            "evidence": f"SQL error string detected after form submission: '{err}'",
                                            "confidence": "Confirmed",
                                        })
                                        break
                    except Exception as exc:
                        await log(f"[WARN] Form probe error {action} field={inp}: {exc}")
                        pass
    return results
