"""Evidence-first proof tasks for findings."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, HTTPException

import db.store as store
from api.models import FindingStatus, ScanProfile, ScanStage, ScanState, ScanStatus
from scanner.engine import run_scan
from scanner.safety import TargetSafetyError, ensure_public_target

router = APIRouter(prefix="/api/proof", tags=["proof"])


@router.post("/{finding_id}/task")
async def create_proof_task(finding_id: str):
    finding = await store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    task_id = f"PRF-{uuid.uuid4().hex[:8].upper()}"
    payload = {
        "id": task_id,
        "finding_id": finding_id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "target": finding.target,
        "status": "queued",
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "result": "",
        "evidence": "",
        "proof_type": "scoped-retest",
        "retest_scan_id": "",
    }
    await store.save_proof_task(task_id, finding_id, payload)
    await store.push_log(finding.scan_id, f"[INFO] Proof task queued: {task_id} for {finding_id}")
    return payload


@router.get("/tasks")
async def list_proof_tasks(finding_id: str | None = None):
    return await store.list_proof_tasks(finding_id)


@router.post("/{task_id}/run")
async def run_proof_task(task_id: str, bg: BackgroundTasks):
    task = await store.get_proof_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Proof task not found")
    finding = await store.get_finding(task["finding_id"])
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    original_scan = await store.get_scan(finding.scan_id)
    confirmed = finding.confidence == "Confirmed"
    if original_scan and original_scan.config.authorized:
        try:
            await ensure_public_target(finding.target)
        except TargetSafetyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        config = original_scan.config.model_copy(deep=True)
        config.target = finding.target
        config.imported_urls = [finding.target]
        config.imported_requests = []
        config.profile = ScanProfile.quick
        config.max_requests = min(config.max_requests, 120)
        config.depth = min(config.depth, 2)

        retest_scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
        state = ScanState(
            id=retest_scan_id,
            config=config,
            status=ScanStatus.pending,
            stage=ScanStage.validate,
            progress=0,
            started_at=datetime.utcnow(),
        )
        await store.create_scan(state)
        bg.add_task(run_scan, retest_scan_id, config)
        finding.status = FindingStatus.in_review
        await store.update_finding(finding)
        task.update({
            "status": "retest-queued",
            "updated_at": datetime.utcnow().isoformat(),
            "result": f"Scoped retest queued as {retest_scan_id}. Review the new scan findings to confirm fixed/open state.",
            "evidence": finding.evidence,
            "severity": finding.severity,
            "retest_scan_id": retest_scan_id,
        })
        await store.save_proof_task(task_id, finding.id, task)
        await store.push_log(finding.scan_id, f"[INFO] Proof task {task_id} queued scoped retest {retest_scan_id}")
        await store.push_log(retest_scan_id, f"[INFO] Scoped proof retest queued from finding {finding.id}")
        return task

    # If no authorized original scan exists, keep proof mode evidence-first and
    # avoid touching the target.
    task.update({
        "status": "passed" if confirmed else "needs-review",
        "updated_at": datetime.utcnow().isoformat(),
        "result": "Confirmed scanner evidence is present." if confirmed else "Finding is tentative; manual validation is recommended. Original scan was not available/authorized for automatic retest.",
        "evidence": finding.evidence,
        "severity": finding.severity,
    })
    await store.save_proof_task(task_id, finding.id, task)
    await store.push_log(finding.scan_id, f"[INFO] Proof task {task_id} completed: {task['status']}")
    return task
