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
import json
import uuid
from datetime import datetime
from typing import Any, Callable, Awaitable

import db.store as store
from api.models import EvidenceArtifact, ScanConfig, ScanState, ScanStatus, ScanStage

from scanner.stages import validate, discover, crawl, probe, analyze, report, passive, wraith_advanced
from scanner.sequence_runner import run_sequence_workflows, sequence_requests_and_urls
from scanner.browser_workflows import browser_results_to_scan_inputs, run_browser_workflows


def _imported_seed_urls(config: ScanConfig) -> list[str]:
    urls = list(config.imported_urls or [])
    for request in config.imported_requests or []:
        url = str(request.get("url") or "").strip()
        if url and url not in urls:
            urls.append(url)
    return urls


def _forms_from_imported_requests(requests: list[dict]) -> list[dict]:
    forms: list[dict] = []
    for request in (requests or [])[:100]:
        url = str(request.get("url") or "").strip()
        if not url:
            continue
        method = str(request.get("method") or "GET").upper()
        headers = _safe_import_headers(request.get("headers") or {})
        body = request.get("body")
        fields = _fields_from_imported_body(body)
        if method in {"POST", "PUT", "PATCH"} and not fields:
            fields = [{"name": "value", "type": "text", "value": "centrix"}]
        forms.append({
            "method": method,
            "action": url,
            "inputs": [field["name"] for field in fields],
            "fields": fields,
            "headers": headers,
            "content_type": request.get("content_type") or headers.get("Content-Type") or headers.get("content-type"),
            "body_template": body,
            "source": "api-import",
            "name": request.get("name") or f"{method} {url}",
        })
    return forms


def _fields_from_imported_body(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            if "=" in body:
                return [{"name": part.split("=", 1)[0], "type": "text", "value": part.split("=", 1)[1]} for part in body.split("&") if "=" in part][:30]
            return [{"name": "body", "type": "text", "value": body[:200]}] if body else []
    if not isinstance(body, dict):
        return []
    fields: list[dict[str, Any]] = []
    for name, value in _flatten_body(body):
        fields.append({"name": name, "type": _field_type(name, value), "value": "" if value is None else str(value)})
    return fields[:40]


def _flatten_body(body: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    flattened: list[tuple[str, Any]] = []
    for key, value in body.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flattened.extend(_flatten_body(value, name))
        elif isinstance(value, list):
            flattened.append((name, value[0] if value else "centrix"))
        else:
            flattened.append((name, value))
    return flattened


def _field_type(name: str, value: Any) -> str:
    lowered = name.lower()
    if "email" in lowered:
        return "email"
    if isinstance(value, (int, float)) or lowered.endswith("id") or lowered == "id":
        return "number"
    return "text"


def _safe_import_headers(headers: dict[str, Any]) -> dict[str, str]:
    blocked = {"host", "content-length", "connection", "accept-encoding"}
    return {str(key): str(value) for key, value in headers.items() if str(key).lower() not in blocked}


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
        imported_seed_urls = _imported_seed_urls(config)
        imported_forms = _forms_from_imported_requests(config.imported_requests)
        if imported_forms:
            await log(f"[INFO] Loaded {len(imported_forms)} imported API request(s) with method/body metadata")
        sequence_forms: list[dict] = []
        sequence_evidence: list[dict] = []
        browser_forms: list[dict] = []
        browser_evidence: list[dict] = []
        if config.sequence_workflows:
            await log(f"[INFO] Running {len(config.sequence_workflows)} API sequence workflow(s)")
            sequence_safety = "intrusive" if getattr(config.safety, "value", str(config.safety)) == "aggressive" else "safe"
            sequence_results = await run_sequence_workflows(
                config.sequence_workflows,
                base_url=config.target,
                safety_mode=sequence_safety,
                timeout=config.timeout,
            )
            sequence_urls, sequence_forms, sequence_evidence = sequence_requests_and_urls(sequence_results)
            imported_seed_urls.extend(url for url in sequence_urls if url not in imported_seed_urls)
            executed = sum(1 for workflow in sequence_results for step in workflow.steps if step.status == "executed")
            skipped = sum(workflow.skipped for workflow in sequence_results)
            failed = [workflow.name for workflow in sequence_results if workflow.status == "failed"]
            await log(f"[INFO] Sequence workflows executed {executed} step(s), skipped {skipped}")
            if failed:
                await log(f"[WARN] Sequence workflow failed: {', '.join(failed)}")
        if config.browser_workflows:
            await log(f"[INFO] Running {len(config.browser_workflows)} browser macro workflow(s)")
            browser_results = await run_browser_workflows(
                config.browser_workflows,
                base_url=config.target,
                timeout=config.timeout,
                headless=True,
            )
            browser_urls, browser_forms, browser_evidence = await browser_results_to_scan_inputs(browser_results)
            imported_seed_urls.extend(url for url in browser_urls if url not in imported_seed_urls)
            executed = sum(1 for workflow in browser_results for step in workflow.steps if step.status == "executed")
            failed = [workflow.name for workflow in browser_results if workflow.status == "failed"]
            await log(f"[INFO] Browser workflows executed {executed} step(s), discovered {len(browser_urls)} URL(s) and {len(browser_forms)} form(s)")
            if failed:
                await log(f"[WARN] Browser workflow failed: {', '.join(failed)}")

        crawl_result = await crawl.run(
            config.target,
            disc_result.get("paths", []),
            log,
            depth=config.depth,
            timeout=config.timeout,
            concurrency=min(config.concurrency, 30),
            scope=config.scope,
            robots_blocked_paths=val_result.get("robots_blocked_paths", []) if config.respect_robots else [],
            max_urls=max(1, config.max_requests // 4),
            seed_urls=imported_seed_urls,
        )

        s = await store.get_scan(scan_id)
        if s:
            s.urls_discovered = len(crawl_result.get("urls", []))
            await store.update_scan(s)
        supplemental_evidence = [*sequence_evidence, *browser_evidence]
        if supplemental_evidence:
            crawl_result["evidence"] = [*supplemental_evidence, *crawl_result.get("evidence", [])]
            crawl_result["urls"] = list(dict.fromkeys([*crawl_result.get("urls", []), *imported_seed_urls]))
        for item in crawl_result.get("evidence", []):
            await store.add_evidence(EvidenceArtifact(id=f"EV-{uuid.uuid4().hex[:10]}", scan_id=scan_id, **item))
        await set_progress(50, ScanStage.crawl)

        # ── Stage 4: Probe ───────────────────────────────────────────────────
        if not await wait_if_paused():
            return
        await set_progress(52, ScanStage.probe)
        probe_forms = [*crawl_result.get("forms", []), *imported_forms, *sequence_forms, *browser_forms]
        raw_vulns = await probe.run(
            config.target,
            crawl_result.get("urls", []),
            crawl_result.get("parameters", []),
            probe_forms,
            log,
            safety=config.safety,
            timeout=config.timeout,
            max_requests=config.max_requests,
        )
        raw_vulns.extend(await wraith_advanced.run(
            config.target,
            crawl_result.get("urls", []),
            probe_forms,
            crawl_result.get("evidence", []),
            log,
            safety=config.safety,
            timeout=config.timeout,
            max_requests=config.max_requests,
        ))
        raw_vulns.extend(await passive.run(crawl_result.get("evidence", []), log))

        # Update request counter (estimate)
        s = await store.get_scan(scan_id)
        if s:
            s.requests_sent = min(config.max_requests, len(crawl_result.get("urls", [])) * 4)
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
