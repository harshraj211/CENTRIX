"""Auth profiles and Wraith-style authorization matrix replay."""
from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any

import aiohttp
from fastapi import APIRouter, HTTPException, Query

import db.store as store
from api.models import AuthMatrixRunRequest, AuthProfile, AuthProfileInput, Finding, FindingStatus, Severity
from scanner.safety import TargetSafetyError, ensure_public_target, url_in_scope

router = APIRouter(prefix="/api/authz", tags=["authz"])


@router.post("/profiles")
async def create_profile(payload: AuthProfileInput):
    profile = AuthProfile(id=f"AUTH-{uuid.uuid4().hex[:8].upper()}", **payload.model_dump())
    await store.save_auth_profile(profile.id, profile.model_dump(mode="json"))
    return _redact_profile(profile.model_dump(mode="json"))


@router.get("/profiles")
async def list_profiles():
    return [_redact_profile(item) for item in await store.list_auth_profiles()]


@router.delete("/profiles/{profile_id}")
async def delete_profile(profile_id: str):
    await store.delete_auth_profile(profile_id)
    return {"deleted": profile_id}


@router.get("/matrix/runs")
async def list_matrix_runs(scan_id: str | None = Query(default=None)):
    return await store.list_auth_matrix_runs(scan_id)


@router.post("/matrix/run")
async def run_authorization_matrix(request: AuthMatrixRunRequest):
    scan = await store.get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.config.authorized:
        raise HTTPException(status_code=403, detail="Scan is not authorised")

    corpus = await store.list_corpus(request.scan_id)
    selected_requests = [item for item in corpus if not request.request_ids or item["id"] in request.request_ids][:30]
    if not selected_requests:
        raise HTTPException(status_code=422, detail="No corpus requests available for matrix replay")

    profiles = []
    for profile_id in request.profile_ids:
        profile = await store.get_auth_profile(profile_id)
        if profile:
            profiles.append(profile)
    if not profiles:
        profiles = [{
            "id": "AUTH-ANON",
            "name": "Anonymous",
            "role": "anonymous",
            "headers": {},
            "cookies": {},
        }]

    run_id = f"AMX-{uuid.uuid4().hex[:8].upper()}"
    rows = []
    findings_created = 0
    for item in selected_requests:
        url = item.get("url", "")
        if not url_in_scope(url, scan.config.target, scan.config.scope):
            continue
        try:
            await ensure_public_target(url)
        except TargetSafetyError:
            continue

        role_results = []
        for profile in profiles:
            result = await _replay_with_profile(item, profile)
            role_results.append(result)
        suspicion = _compare_role_results(role_results)
        row = {
            "request_id": item["id"],
            "method": item.get("method", "GET"),
            "url": url,
            "roles": role_results,
            "suspicious": suspicion["suspicious"],
            "reason": suspicion["reason"],
        }
        rows.append(row)
        if row["suspicious"]:
            finding = Finding(
                id=f"AMX-{uuid.uuid4().hex[:8].upper()}",
                scan_id=request.scan_id,
                title="Authorization Matrix Access Control Weakness",
                severity=Severity.high,
                category="Access Control",
                target=url,
                parameter="role",
                confidence="Tentative",
                status=FindingStatus.open,
                description="Different auth roles received unexpectedly similar successful responses for the same captured request.",
                recommendation="Verify ownership and role checks server-side for this endpoint. Deny lower-privilege roles before returning resource data.",
                evidence=row["reason"],
                cwe="CWE-862",
                cvss=8.1,
            )
            await store.add_finding(request.scan_id, finding)
            findings_created += 1

    payload = {
        "id": run_id,
        "scan_id": request.scan_id,
        "created_at": datetime.utcnow().isoformat(),
        "request_count": len(rows),
        "profile_count": len(profiles),
        "findings_created": findings_created,
        "rows": rows,
    }
    await store.save_auth_matrix_run(run_id, request.scan_id, payload)
    await store.push_log(request.scan_id, f"[INFO] Authorization matrix {run_id} completed: {findings_created} findings")
    return payload


async def _replay_with_profile(item: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    headers = dict(item.get("request_headers") or {})
    headers.update(profile.get("headers") or {})
    cookies = profile.get("cookies") or {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    started = time.perf_counter()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                item.get("method", "GET"),
                item.get("url", ""),
                headers=headers,
                data=item.get("request_body") or None,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=20),
                ssl=False,
            ) as response:
                body = await response.content.read(160_000)
                return {
                    "profile_id": profile.get("id"),
                    "name": profile.get("name"),
                    "role": profile.get("role"),
                    "status": response.status,
                    "length": len(body),
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "success": 200 <= response.status < 300,
                }
    except Exception as exc:
        return {
            "profile_id": profile.get("id"),
            "name": profile.get("name"),
            "role": profile.get("role"),
            "status": 0,
            "length": 0,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            "success": False,
            "error": str(exc),
        }


def _compare_role_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [item for item in results if item.get("success")]
    roles = {str(item.get("role", "")).lower() for item in successful}
    if len(successful) < 2:
        return {"suspicious": False, "reason": "Fewer than two roles had successful access"}
    privileged = [item for item in successful if str(item.get("role", "")).lower() in {"admin", "owner", "manager"}]
    lower = [item for item in successful if str(item.get("role", "")).lower() in {"anonymous", "user", "viewer", "guest"}]
    if not privileged or not lower:
        return {"suspicious": False, "reason": "No privileged/lower-role comparison was available"}
    for high in privileged:
        for low in lower:
            length_delta = abs(int(high.get("length", 0)) - int(low.get("length", 0)))
            if high.get("status") == low.get("status") and length_delta <= max(80, int(max(high.get("length", 0), low.get("length", 0)) * 0.08)):
                return {
                    "suspicious": True,
                    "reason": f"Lower role '{low.get('role')}' received a response similar to privileged role '{high.get('role')}'",
                }
    return {"suspicious": False, "reason": f"Successful roles were not similar enough to flag: {sorted(roles)}"}


def _redact_profile(profile: dict[str, Any]) -> dict[str, Any]:
    redacted = dict(profile)
    redacted["headers"] = {
        key: ("<set>" if key.lower() in {"authorization", "cookie", "x-api-key"} else value)
        for key, value in (profile.get("headers") or {}).items()
    }
    redacted["cookies"] = {key: "<set>" for key in (profile.get("cookies") or {}).keys()}
    return redacted
