"""
Scanner Engine — Orchestrates all 6 stages sequentially.
Pushes progress updates and log lines to the store's asyncio.Queue
so the WebSocket handler can stream them to the frontend in real-time.

Progress milestones:
  validate  →  0-10%
  discover  → 10-25%
  crawl     → 25-50%
  probe     → 50-80%
  analyze   → 80-92%
  report    → 92-100%
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Callable, Awaitable

import db.store as store
from api.models import ScanConfig, ScanState, ScanStatus, ScanStage

from scanner.stages import validate, discover, crawl, probe, analyze, report


async def run_scan(scan_id: str, config: ScanConfig) -> None:
    # ── helpers ──────────────────────────────────────────────────────────────
    async def log(msg: str) -> None:
        await store.push_log(scan_id, msg)

    async def set_progress(pct: int, stage: ScanStage) -> None:
        state = await store.get_scan(scan_id)
        if state:
            state.progress = pct
            state.stage = stage
            state.status = ScanStatus.running
            await store.update_scan(state)

    async def wait_if_paused() -> bool:
        """Returns False if scan was stopped."""
        while True:
            state = await store.get_scan(scan_id)
            if not state:
                return False
            if state.status == ScanStatus.stopped:
                return False
            if state.status != ScanStatus.paused:
                return True
            await asyncio.sleep(0.5)

    # ── Mark running ─────────────────────────────────────────────────────────
    state = await store.get_scan(scan_id)
    if not state:
        return
    state.status = ScanStatus.running
    state.started_at = datetime.utcnow()
    await store.update_scan(state)

    await log(f"[INFO] VulnGuard Engine v4.0 — Scan {scan_id} started")
    await log(f"[INFO] Target: {config.target} | Profile: {config.profile} | Safety: {config.safety}")

    try:
        # ── Stage 1: Validate ────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(2, ScanStage.validate)
        val_result = await validate.run(config.target, log, timeout=config.timeout)
        await set_progress(10, ScanStage.validate)

        # ── Stage 2: Discover ────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(12, ScanStage.discover)

        if config.safety == "passive":
            disc_result = {"open_ports": [], "paths": []}
            await log("[INFO] Skipping active discovery in passive mode")
        else:
            disc_result = await discover.run(
                config.target, log,
                timeout=config.timeout,
                concurrency=min(config.concurrency, 20),
            )

        # Update urls_discovered counter
        s = await store.get_scan(scan_id)
        if s:
            s.urls_discovered = len(disc_result.get("paths", []))
            await store.update_scan(s)
        await set_progress(25, ScanStage.discover)

        # ── Stage 3: Crawl ───────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(27, ScanStage.crawl)
        crawl_result = await crawl.run(
            config.target,
            disc_result.get("paths", []),
            log,
            depth=config.depth,
            timeout=config.timeout,
            concurrency=min(config.concurrency, 30),
        )

        s = await store.get_scan(scan_id)
        if s:
            s.urls_discovered = len(crawl_result.get("urls", []))
            await store.update_scan(s)
        await set_progress(50, ScanStage.crawl)

        # ── Stage 4: Probe ───────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(52, ScanStage.probe)
        raw_vulns = await probe.run(
            config.target,
            crawl_result.get("urls", []),
            crawl_result.get("parameters", []),
            crawl_result.get("forms", []),
            log,
            safety=config.safety,
            timeout=config.timeout,
        )

        # Update request counter (estimate)
        s = await store.get_scan(scan_id)
        if s:
            s.requests_sent = len(crawl_result.get("urls", [])) * 4  # approx
            await store.update_scan(s)
        await set_progress(80, ScanStage.probe)

        # ── Stage 5: Analyze ─────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(82, ScanStage.analyze)
        findings = await analyze.run(scan_id, raw_vulns, log)

        # Persist findings
        for f in findings:
            await store.add_finding(scan_id, f)

        s = await store.get_scan(scan_id)
        if s:
            s.findings_count = len(findings)
            await store.update_scan(s)
        await set_progress(92, ScanStage.analyze)

        # ── Stage 6: Report ──────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(95, ScanStage.report)
        await report.run(scan_id, findings, log)

        # ── Finalize ─────────────────────────────────────────────────────────
        s = await store.get_scan(scan_id)
        if s:
            s.status = ScanStatus.completed
            s.stage = ScanStage.done
            s.progress = 100
            s.finished_at = datetime.utcnow()
            s.duration_s = (s.finished_at - s.started_at).total_seconds()
            await store.update_scan(s)

        await log(f"[SUCCESS] Scan {scan_id} finished — {len(findings)} findings in "
                  f"{s.duration_s:.0f}s")

    except Exception as exc:
        s = await store.get_scan(scan_id)
        if s:
            s.status = ScanStatus.error
            s.error_msg = str(exc)
            s.finished_at = datetime.utcnow()
            await store.update_scan(s)
        await log(f"[ERROR] Scan failed: {exc}")

    finally:
        # Signal WebSocket consumers to close
        await store.push_log(scan_id, "__DONE__")
