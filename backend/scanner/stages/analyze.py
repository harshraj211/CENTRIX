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
    "csrf": "CWE-352",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "traversal": "CWE-22",
    "open_redirect": "CWE-601",
    "missing_header": "CWE-693",
    "idor": "CWE-284",
    "ssrf": "CWE-918",
    "jwt": "CWE-200",
    "graphql": "CWE-200",
    "graphql_introspection": "CWE-200",
    "websocket": "CWE-200",
    "ssti": "CWE-94",
    "hpp": "CWE-235",
    "command_injection": "CWE-78",
    "rce": "CWE-78",
    "xxe": "CWE-611",
    "mass_assignment": "CWE-915",
    "race_condition": "CWE-362",
    "vulnerable_component": "CWE-1104",
    "crypto": "CWE-319",
    "wordpress": "CWE-200",
    "graphql_dos": "CWE-400",
    "graphql_batching": "CWE-770",
    "grpc_reflection": "CWE-200",
    "flag": "CWE-200",
}

_CVSS_MAP: dict[str, float] = {
    "csrf": 6.5,
    "sqli": 9.8,
    "xss": 7.2,
    "traversal": 9.1,
    "open_redirect": 6.1,
    "missing_header": 5.3,
    "idor": 8.1,
    "ssrf": 9.3,
    "jwt": 5.3,
    "graphql": 3.1,
    "graphql_introspection": 5.3,
    "websocket": 3.1,
    "ssti": 9.1,
    "hpp": 5.3,
    "command_injection": 10.0,
    "rce": 10.0,
    "xxe": 8.6,
    "mass_assignment": 8.1,
    "race_condition": 7.1,
    "vulnerable_component": 7.5,
    "crypto": 6.5,
    "wordpress": 5.3,
    "graphql_dos": 7.5,
    "graphql_batching": 8.1,
    "grpc_reflection": 5.3,
    "flag": 7.5,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "csrf": Severity.medium,
    "sqli": Severity.critical,
    "xss": Severity.high,
    "traversal": Severity.critical,
    "open_redirect": Severity.medium,
    "missing_header": Severity.low,
    "idor": Severity.high,
    "ssrf": Severity.critical,
    "jwt": Severity.low,
    "graphql": Severity.info,
    "graphql_introspection": Severity.low,
    "websocket": Severity.info,
    "ssti": Severity.critical,
    "hpp": Severity.medium,
    "command_injection": Severity.critical,
    "rce": Severity.critical,
    "xxe": Severity.high,
    "mass_assignment": Severity.high,
    "race_condition": Severity.medium,
    "vulnerable_component": Severity.high,
    "crypto": Severity.medium,
    "wordpress": Severity.low,
    "graphql_dos": Severity.high,
    "graphql_batching": Severity.high,
    "grpc_reflection": Severity.low,
    "flag": Severity.high,
}

_TITLE_MAP: dict[str, str] = {
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "sqli": "SQL Injection",
    "xss": "Reflected Cross-Site Scripting (XSS)",
    "traversal": "Path Traversal",
    "open_redirect": "Open Redirect",
    "missing_header": "Missing Security Header",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "jwt": "JWT Token Exposure",
    "graphql": "GraphQL Surface Detected",
    "graphql_introspection": "GraphQL Introspection Enabled",
    "websocket": "WebSocket Surface Detected",
    "ssti": "Server-Side Template Injection (SSTI)",
    "hpp": "HTTP Parameter Pollution",
    "command_injection": "Command Injection",
    "rce": "Remote Code Execution",
    "xxe": "XML External Entity (XXE)",
    "mass_assignment": "Mass Assignment",
    "race_condition": "Race Condition",
    "vulnerable_component": "Vulnerable or Outdated Component",
    "crypto": "Cryptographic / Transport Weakness",
    "wordpress": "WordPress Exposure",
    "graphql_dos": "GraphQL Depth/Complexity Weakness",
    "graphql_batching": "GraphQL Batching Bypass",
    "grpc_reflection": "gRPC Reflection Enabled",
    "flag": "Sensitive Flag or Secret Exposure",
}

_CATEGORY_MAP: dict[str, str] = {
    "csrf": "Access Control",
    "sqli": "Injection",
    "xss": "XSS",
    "traversal": "Path Traversal",
    "open_redirect": "Redirect",
    "missing_header": "Security Headers",
    "idor": "Access Control",
    "ssrf": "SSRF",
    "jwt": "Authentication",
    "graphql": "API Surface",
    "graphql_introspection": "API Surface",
    "websocket": "API Surface",
    "ssti": "Injection",
    "hpp": "Input Handling",
    "command_injection": "Injection",
    "rce": "Injection",
    "xxe": "Injection",
    "mass_assignment": "Access Control",
    "race_condition": "Business Logic",
    "vulnerable_component": "Components",
    "crypto": "Cryptography",
    "wordpress": "CMS",
    "graphql_dos": "API Surface",
    "graphql_batching": "API Surface",
    "grpc_reflection": "API Surface",
    "flag": "Sensitive Data",
}

_RECOMMENDATION_MAP: dict[str, str] = {
    "csrf": "Use framework-generated anti-CSRF tokens on all state-changing requests and validate SameSite cookie protections.",
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
    "jwt": (
        "Avoid returning tokens in cacheable responses or logs. Mark token cookies HttpOnly, Secure, and SameSite, "
        "and keep token lifetimes short."
    ),
    "graphql": (
        "Review GraphQL authorization, disable introspection in production where appropriate, "
        "and enforce query depth and complexity limits."
    ),
    "graphql_introspection": (
        "Disable GraphQL introspection in production where appropriate, require authentication for schema access, "
        "and enforce query complexity limits."
    ),
    "websocket": (
        "Require authentication and origin checks during WebSocket upgrades, and validate every message server-side."
    ),
    "ssti": (
        "Do not render untrusted input as template source. Use safe template APIs and strict allowlists for dynamic content."
    ),
    "hpp": (
        "Canonicalize duplicate parameters before authorization and validation. Reject ambiguous requests at the edge."
    ),
    "command_injection": (
        "Avoid shell invocation with user input. Use language-native APIs and allowlist any permitted command arguments."
    ),
    "rce": (
        "Never pass user input to shell commands. "
        "Use language-native APIs instead of shell invocations."
    ),
    "xxe": (
        "Disable external entity resolution in XML parsers and reject untrusted XML where possible."
    ),
    "mass_assignment": (
        "Bind only allowlisted fields server-side. Ignore privilege fields such as role, is_admin, and permissions from client input."
    ),
    "race_condition": (
        "Protect state-changing operations with server-side locking, idempotency keys, or transaction constraints."
    ),
    "vulnerable_component": (
        "Upgrade the affected component to a supported version and remove version disclosures where possible."
    ),
    "crypto": (
        "Enforce HTTPS, secure cookies, modern TLS, HSTS, and avoid exposing sensitive values in responses."
    ),
    "wordpress": (
        "Restrict exposed WordPress endpoints, remove unnecessary public files, and keep WordPress/core plugins updated."
    ),
    "graphql_dos": (
        "Enforce GraphQL query depth, complexity, cost, timeout, and rate limits."
    ),
    "graphql_batching": (
        "Apply authentication, authorization, and rate limits per operation inside GraphQL batched requests."
    ),
    "grpc_reflection": (
        "Disable gRPC reflection in production unless it is required and protected by authentication."
    ),
    "flag": (
        "Remove exposed secrets/flags from responses and rotate any sensitive values that may have leaked."
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
    suppressed_noise = 0

    for vuln in raw_vulns:
        vtype = vuln.get("type", "unknown")
        if vtype == "missing_header":
            suppressed_noise += 1
            continue

        url = vuln.get("url", "")
        param = vuln.get("param", "")
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")
        confidence = vuln.get("confidence", "Tentative")

        # Dedup key: hash of (type, url, param) — O(1) set lookup
        dedup_basis = f"{vtype}:{str(param).lower()}" if vtype == "missing_header" else f"{vtype}:{url}:{param}"
        dedup_key = hashlib.md5(dedup_basis.encode()).hexdigest()
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
    if suppressed_noise:
        await log(f"[INFO] Suppressed {suppressed_noise} missing security-header telemetry items")
    return findings
