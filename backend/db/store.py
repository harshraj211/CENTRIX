"""
In-memory store — all lookups are O(1) dict access.
asyncio.Lock ensures safe concurrent writes from scan tasks.
"""
from __future__ import annotations

import asyncio
from typing import Any

from api.models import Finding, ScanState

# ── Primary stores ──────────────────────────────────────────────
# keyed by scan_id (str)
_scans: dict[str, ScanState] = {}
_scan_findings: dict[str, list[Finding]] = {}
_scan_logs: dict[str, asyncio.Queue] = {}   # live log queues per scan
_reports: dict[str, dict[str, Any]] = {}

# Single shared lock – contention is minimal (one scan at a time typically)
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


# ── Scans ────────────────────────────────────────────────────────
async def create_scan(scan: ScanState) -> None:
    async with _get_lock():
        _scans[scan.id] = scan
        _scan_findings[scan.id] = []
        _scan_logs[scan.id] = asyncio.Queue()


async def get_scan(scan_id: str) -> ScanState | None:
    return _scans.get(scan_id)


async def update_scan(scan: ScanState) -> None:
    async with _get_lock():
        _scans[scan.id] = scan


async def list_scans() -> list[ScanState]:
    return list(_scans.values())


# ── Findings ─────────────────────────────────────────────────────
async def add_finding(scan_id: str, finding: Finding) -> None:
    async with _get_lock():
        if scan_id not in _scan_findings:
            _scan_findings[scan_id] = []
        _scan_findings[scan_id].append(finding)


async def get_findings(scan_id: str) -> list[Finding]:
    return _scan_findings.get(scan_id, [])


async def get_all_findings() -> list[Finding]:
    result: list[Finding] = []
    for findings in _scan_findings.values():
        result.extend(findings)
    return result


# ── Live log queues ───────────────────────────────────────────────
def get_log_queue(scan_id: str) -> asyncio.Queue | None:
    return _scan_logs.get(scan_id)


async def push_log(scan_id: str, msg: str) -> None:
    q = _scan_logs.get(scan_id)
    if q:
        await q.put(msg)


# ── Reports ───────────────────────────────────────────────────────
async def save_report(report_id: str, data: dict[str, Any]) -> None:
    async with _get_lock():
        _reports[report_id] = data


async def get_report(report_id: str) -> dict[str, Any] | None:
    return _reports.get(report_id)


async def list_reports() -> list[dict[str, Any]]:
    return list(_reports.values())
