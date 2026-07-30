"""
Stage 6 — Report Aggregation
Builds the final summary pushed into the store.
"""
from __future__ import annotations

from typing import Callable, Awaitable

from api.models import Finding


async def run(
    scan_id: str,
    findings: list[Finding],
    log: Callable[[str], Awaitable[None]],
) -> dict:
    """Returns summary statistics for the completed scan."""
    await log("[INFO] Generating final scan report...")

    severity_counts: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }
    for f in findings:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary = {
        "scan_id": scan_id,
        "total": len(findings),
        "by_severity": severity_counts,
        "top_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity.value, "target": f.target}
            for f in sorted(
                findings,
                key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                              .get(x.severity.value, 5),
            )[:5]
        ],
    }

    await log(
        f"[SUCCESS] Scan completed — "
        f"{severity_counts['Critical']} Critical, "
        f"{severity_counts['High']} High, "
        f"{severity_counts['Medium']} Medium, "
        f"{severity_counts['Low']} Low"
    )
    return summary
