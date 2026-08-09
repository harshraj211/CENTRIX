"""Wraith-style scheduled and repeat scan queue."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import db.store as store
from api.models import ScanConfig, ScanStage, ScanState, ScanStatus, StartScanResponse
from scanner.engine import run_scan
from scanner.safety import TargetSafetyError, ensure_public_target, normalise_target

router = APIRouter(prefix="/api/schedules", tags=["schedules"])

Frequency = Literal["once", "hourly", "daily", "weekly"]
ScheduleStatus = Literal["enabled", "paused", "completed"]


class ScheduleInput(BaseModel):
    name: str = Field(default="Scheduled scan")
    config: ScanConfig
    frequency: Frequency = "daily"
    first_run_at: datetime | None = None


class ScheduleToggle(BaseModel):
    status: ScheduleStatus


async def scheduler_loop() -> None:
    """Small local scheduler. No Redis/Celery required for the desktop app."""
    while True:
        try:
            await dispatch_due_schedules()
        except Exception:
            pass
        await asyncio.sleep(30)


async def dispatch_due_schedules() -> list[dict[str, Any]]:
    now = datetime.utcnow()
    dispatched = []
    for schedule in await store.list_scheduled_scans():
        if schedule.get("status") != "enabled":
            continue
        due_at = _parse_dt(schedule.get("next_run_at"))
        if due_at and due_at <= now:
            dispatched.append(await _dispatch_schedule(schedule))
    return dispatched


@router.get("")
async def list_schedules():
    return await store.list_scheduled_scans()


@router.post("")
async def create_schedule(payload: ScheduleInput):
    config = payload.config
    if not config.authorized:
        raise HTTPException(status_code=422, detail="Confirm authorization before scheduling this scan.")
    try:
        config.target = normalise_target(config.target)
        await ensure_public_target(config.target)
    except TargetSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    now = datetime.utcnow()
    first_run = payload.first_run_at or now
    schedule_id = f"SCH-{uuid.uuid4().hex[:8].upper()}"
    schedule = {
        "id": schedule_id,
        "name": payload.name.strip() or "Scheduled scan",
        "frequency": payload.frequency,
        "status": "enabled",
        "config": config.model_dump(mode="json"),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "next_run_at": first_run.isoformat(),
        "last_run_at": "",
        "last_scan_id": "",
        "run_count": 0,
        "history": [],
    }
    await store.save_scheduled_scan(schedule_id, schedule)
    return schedule


@router.post("/{schedule_id}/run", response_model=StartScanResponse)
async def run_schedule_now(schedule_id: str):
    schedule = await store.get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    dispatched = await _dispatch_schedule(schedule, manual=True)
    return StartScanResponse(
        scan_id=dispatched["last_scan_id"],
        status=ScanStatus.pending,
        message=f"Scheduled scan {dispatched['last_scan_id']} queued from {schedule_id}",
    )


@router.patch("/{schedule_id}/status")
async def update_schedule_status(schedule_id: str, payload: ScheduleToggle):
    schedule = await store.get_scheduled_scan(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    schedule["status"] = payload.status
    schedule["updated_at"] = datetime.utcnow().isoformat()
    if payload.status == "enabled" and not schedule.get("next_run_at"):
        schedule["next_run_at"] = datetime.utcnow().isoformat()
    await store.save_scheduled_scan(schedule_id, schedule)
    return schedule


@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str):
    if not await store.get_scheduled_scan(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    await store.delete_scheduled_scan(schedule_id)
    return {"id": schedule_id, "deleted": True}


async def _dispatch_schedule(schedule: dict[str, Any], manual: bool = False) -> dict[str, Any]:
    config = ScanConfig.model_validate(schedule["config"])
    scan_id = f"SCN-{uuid.uuid4().hex[:8].upper()}"
    state = ScanState(
        id=scan_id,
        config=config,
        status=ScanStatus.pending,
        stage=ScanStage.validate,
        progress=0,
        started_at=datetime.utcnow(),
    )
    await store.create_scan(state)
    asyncio.create_task(run_scan(scan_id, config))

    now = datetime.utcnow()
    schedule["last_run_at"] = now.isoformat()
    schedule["last_scan_id"] = scan_id
    schedule["run_count"] = int(schedule.get("run_count") or 0) + 1
    schedule["history"] = ([{"scan_id": scan_id, "queued_at": now.isoformat(), "manual": manual}] + list(schedule.get("history") or []))[:20]
    schedule["updated_at"] = now.isoformat()
    schedule["next_run_at"] = _next_run(schedule.get("frequency") or "once", now)
    if schedule.get("frequency") == "once" and not manual:
        schedule["status"] = "completed"
    await store.save_scheduled_scan(schedule["id"], schedule)
    await store.push_log(scan_id, f"[INFO] Scan queued by schedule {schedule['id']} ({schedule.get('name')})")
    return schedule


def _next_run(frequency: str, from_time: datetime) -> str:
    if frequency == "hourly":
        return (from_time + timedelta(hours=1)).isoformat()
    if frequency == "daily":
        return (from_time + timedelta(days=1)).isoformat()
    if frequency == "weekly":
        return (from_time + timedelta(days=7)).isoformat()
    return ""


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None
