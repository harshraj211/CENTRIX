"""Local OOB collaborator hooks for safe proof workflows."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Request

import db.store as store

router = APIRouter(prefix="/api/oob", tags=["oob"])


@router.post("/token")
async def create_oob_token(scan_id: str = "", finding_id: str = ""):
    token = f"oob-{uuid.uuid4().hex[:12]}"
    return {
        "token": token,
        "scan_id": scan_id,
        "finding_id": finding_id,
        "http_callback_path": f"/api/oob/hit/{token}",
        "note": "Expose the Centrix backend through a public tunnel for external target callbacks.",
    }


@router.api_route("/hit/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def record_oob_hit(token: str, request: Request):
    body = await request.body()
    event_id = f"OOB-{uuid.uuid4().hex[:10].upper()}"
    payload = {
        "id": event_id,
        "token": token,
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "body_excerpt": body[:2048].decode("utf-8", errors="replace"),
        "client": request.client.host if request.client else "",
        "captured_at": datetime.utcnow().isoformat(),
    }
    await store.save_oob_event(event_id, token, payload)
    return {"ok": True, "event_id": event_id}


@router.get("/events")
async def list_oob_events(token: str | None = None):
    return await store.list_oob_events(token)
