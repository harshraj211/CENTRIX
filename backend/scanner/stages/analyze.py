"""
Stage 5 — Vulnerability Analysis
- Maps raw probe results → structured Finding objects
- CWE / CVSS mapping via O(1) dict lookup
- Deduplication by (url, param, type) hash — O(1) set membership
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Callable, Awaitable

from api.models import Finding, Severity, FindingStatus

# ── Static lookup tables — O(1) ────────────────────────────────────────────
_CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "traversal": "CWE-22",
    "open_redirect": "CWE-601",
    "missing_header": "CWE-693",
    "idor": "CWE-284",
    "ssrf": "CWE-918",
    "rce": "CWE-78",
}

_CVSS_MAP: dict[str, float] = {
    "sqli": 9.8,
    "xss": 7.2,
    "traversal": 9.1,
    "open_redirect": 6.1,
    "missing_header": 5.3,
    "idor": 8.1,
    "ssrf": 9.3,
    "rce": 10.0,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "sqli": Severity.critical,
    "xss": Severity.high,
    "traversal": Severity.critical,
    "open_redirect": Severity.medium,
    "missing_header": Severity.low,
    "idor": Severity.high,
    "ssrf": Severity.critical,
    "rce": Severity.critical,
}

_TITLE_MAP: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Reflected Cross-Site Scripting (XSS)",
    "traversal": "Path Traversal",
    "open_redirect": "Open Redirect",
    "missing_header": "Missing Security Header",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "rce": "Remote Code Execution",
}

_CATEGORY_MAP: dict[str, str] = {
    "sqli": "Injection",
    "xss": "XSS",
    "traversal": "Path Traversal",
    "open_redirect": "Redirect",
    "missing_header": "Security Headers",
    "idor": "Access Control",
    "ssrf": "SSRF",
    "rce": "Injection",
}

_RECOMMENDATION_MAP: dict[str, str] = {
    "sqli": (
        "Use parameterized queries or prepared statements for all database interactions. "
        "Never concatenate user input into SQL strings. Adopt an ORM with built-in protections."
    ),
    "xss": (
        "HTML-encode all user-supplied data before rendering. "
        "Implement a strict Content-Security-Policy. Avoid innerHTML."
    ),
    "traversal": (
        "Validate and sanitize file path parameters against an allowlist. "
        "Use path.resolve() and verify the result starts within the intended directory."
    ),
    "open_redirect": (
        "Validate redirect destinations against an allowlist. "
        "Avoid using user-supplied input in Location headers directly."
    ),
    "missing_header": (
        "Add the missing security header to all HTTP responses. "
        "Configure it in the web server or application middleware."
    ),
    "idor": (
        "Implement ownership checks on all resource access. "
        "Use random UUIDs instead of sequential IDs and enforce authorization at the data layer."
    ),
    "ssrf": (
        "Validate and allowlist URLs that the server is permitted to fetch. "
        "Block requests to internal IP ranges (169.254.0.0/16, 10.0.0.0/8, etc.)."
    ),
    "rce": (
        "Never pass user input to shell commands. "
        "Use language-native APIs instead of shell invocations."
    ),
}


async def run(
    scan_id: str,
    raw_vulns: list[dict],
    log: Callable[[str], Awaitable[None]],
) -> list[Finding]:
    """Deduplicates and converts raw probe results to Finding objects."""
    await log(f"[INFO] Analyzing {len(raw_vulns)} raw vulnerability candidates...")

    seen: set[str] = set()   # O(1) dedup key
    findings: list[Finding] = []

    for vuln in raw_vulns:
        vtype = vuln.get("type", "unknown")
        url = vuln.get("url", "")
        param = vuln.get("param", "")
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")
        confidence = vuln.get("confidence", "Tentative")

        # Dedup key: hash of (type, url, param) — O(1) set lookup
        dedup_key = hashlib.md5(f"{vtype}:{url}:{param}".encode()).hexdigest()
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        title = _TITLE_MAP.get(vtype, vtype.replace("_", " ").title())
        if vtype == "missing_header":
            title = f"Missing Security Header: {param}"

        finding = Finding(
            id=f"VLN-{uuid.uuid4().hex[:6].upper()}",
            scan_id=scan_id,
            title=title,
            severity=_SEVERITY_MAP.get(vtype, Severity.info),
            category=_CATEGORY_MAP.get(vtype, "Misc"),
            target=url,
            parameter=param,
            confidence=confidence,
            status=FindingStatus.open,
            found_at=datetime.utcnow(),
            description=f"Detected via active probe. Payload used: `{payload[:100]}`",
            recommendation=_RECOMMENDATION_MAP.get(vtype, "Review and remediate."),
            evidence=evidence,
            cwe=_CWE_MAP.get(vtype),
            cvss=_CVSS_MAP.get(vtype),
        )
        findings.append(finding)
        sev = finding.severity.value
        await log(f"[{'CRITICAL' if sev == 'Critical' else 'ALERT'}] "
                  f"{sev} — {title} @ {url} [{param}]")

    await log(f"[SUCCESS] Analysis complete — {len(findings)} unique findings")
    return findings
