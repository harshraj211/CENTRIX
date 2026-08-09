"""Safe manual DAST workbench operations adapted from Wraith.

This is intentionally scoped: Centrix can replay, compare, fuzz, save, and
passively analyze authorised traffic, while refusing out-of-scope targets.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import uuid
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlparse

import aiohttp
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

import db.store as store
from api.models import EvidenceArtifact, Finding, FindingStatus, ManualRequest, ResponseComparison, Severity
from scanner.safety import TargetSafetyError, ensure_public_target, url_in_scope
from scanner.manual.browser_launcher import CentrixBrowserController
from scanner.manual.certificates import CentrixCAManager
from scanner.manual.capture_proxy import CaptureProxyConfig, CentrixCaptureProxy
from scanner.stages import passive

router = APIRouter(prefix="/api/manual", tags=["manual"])
_ca_manager = CentrixCAManager()
_browser = CentrixBrowserController()
_capture_proxy = CentrixCaptureProxy()

_proxy_state: dict[str, Any] = {
    "running": False,
    "host": "127.0.0.1",
    "port": 8088,
    "mode": "safe-forward",
    "https_mitm": False,
    "started_at": None,
}


class SaveRequestPayload(ManualRequest):
    response: dict[str, Any] | None = None
    note: str = ""


class ManualFindingPayload(BaseModel):
    request_id: str | None = None
    title: str
    vuln_type: str = "manual"
    severity: Severity = Severity.medium
    parameter: str = ""
    evidence: str = ""
    recommendation: str = "Review the captured request/response and remediate the issue."


class IntruderPayload(ManualRequest):
    marker: str = "{{payload}}"
    payloads: list[str] = Field(default_factory=list, max_length=100)
    delay_ms: int = Field(default=100, ge=0, le=2000)
    max_requests: int = Field(default=25, ge=1, le=100)
    match_text: str = ""
    extract_regex: str = ""


class DecodePayload(BaseModel):
    mode: Literal["url-decode", "url-encode", "base64-decode", "base64-encode", "json-pretty", "hash-sha256"]
    value: str


async def _validate_request(request: ManualRequest) -> None:
    scan = await store.get_scan(request.scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.config.authorized:
        raise HTTPException(status_code=403, detail="The scan has no authorization confirmation")
    if not url_in_scope(request.url, scan.config.target, scan.config.scope):
        raise HTTPException(status_code=422, detail="Manual requests must stay within the saved scan scope")
    try:
        await ensure_public_target(request.url)
    except TargetSafetyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


async def _send(request: ManualRequest) -> dict[str, Any]:
    started = time.perf_counter()
    async with aiohttp.ClientSession() as session:
        async with session.request(
            request.method,
            request.url,
            headers=request.headers,
            data=request.body,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=30),
            ssl=False,
        ) as response:
            body = await response.content.read(512_000)
            text = body.decode(response.charset or "utf-8", errors="replace")
            return {
                "status": response.status,
                "headers": dict(response.headers),
                "body": text,
                "length": len(body),
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                "content_type": response.headers.get("Content-Type", ""),
            }


def _corpus_payload(request: ManualRequest, response: dict[str, Any] | None = None, note: str = "") -> dict[str, Any]:
    item_id = f"REQ-{uuid.uuid4().hex[:10].upper()}"
    parsed = urlparse(request.url)
    return {
        "id": item_id,
        "scan_id": request.scan_id,
        "method": request.method,
        "url": request.url,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "request_headers": request.headers,
        "request_body": request.body or "",
        "response": response or {},
        "status": response.get("status") if response else None,
        "content_type": response.get("content_type") if response else "",
        "response_length": response.get("length") if response else 0,
        "response_excerpt": (response.get("body") or "")[:1500] if response else "",
        "note": note,
        "captured_at": datetime.utcnow().isoformat(),
        "source": "manual",
    }


async def _save_corpus_payload(payload: dict[str, Any]) -> dict[str, Any]:
    await store.add_corpus_item(payload["scan_id"], payload["id"], payload)
    response = payload.get("response") or {}
    if response:
        await store.add_evidence(EvidenceArtifact(
            id=f"EV-{uuid.uuid4().hex[:10].upper()}",
            scan_id=payload["scan_id"],
            url=payload["url"],
            method=payload["method"],
            status_code=int(response.get("status") or 0),
            content_type=str(response.get("content_type") or ""),
            response_length=int(response.get("length") or 0),
            response_excerpt=str(response.get("body") or "")[:1500],
            response_headers=response.get("headers") or {},
        ))
    return payload


@router.post("/replay")
async def replay_request(request: ManualRequest):
    await _validate_request(request)
    try:
        result = await _send(request)
    except aiohttp.ClientError as exc:
        raise HTTPException(status_code=502, detail=f"Request failed: {exc}") from exc
    payload = await _save_corpus_payload(_corpus_payload(request, result))
    await store.push_log(request.scan_id, f"[INFO] Manual {request.method} replay: {urlparse(request.url).path} -> {result['status']}")
    return {**result, "request_id": payload["id"]}


@router.post("/save-request")
async def save_request(request: SaveRequestPayload):
    await _validate_request(request)
    payload = await _save_corpus_payload(_corpus_payload(request, request.response, request.note))
    await store.push_log(request.scan_id, f"[INFO] Saved manual request to corpus: {payload['id']}")
    return payload


@router.get("/corpus")
async def list_corpus(scan_id: str | None = Query(default=None)):
    return await store.list_corpus(scan_id)


@router.get("/corpus/{request_id}")
async def get_corpus_request(request_id: str):
    item = await store.get_corpus_item(request_id)
    if not item:
        raise HTTPException(status_code=404, detail="Request not found")
    return item


@router.post("/compare-responses", response_model=ResponseComparison)
async def compare_responses(left: dict, right: dict):
    left_status, right_status = int(left.get("status", 0)), int(right.get("status", 0))
    left_body, right_body = str(left.get("body", "")), str(right.get("body", ""))
    left_length, right_length = int(left.get("length", len(left_body))), int(right.get("length", len(right_body)))
    return ResponseComparison(
        left_status=left_status,
        right_status=right_status,
        left_length=left_length,
        right_length=right_length,
        status_changed=left_status != right_status,
        length_delta=right_length - left_length,
    )


@router.post("/compare-corpus")
async def compare_corpus(left_id: str, right_id: str):
    left = await store.get_corpus_item(left_id)
    right = await store.get_corpus_item(right_id)
    if not left or not right:
        raise HTTPException(status_code=404, detail="One or both corpus items were not found")
    left_response = left.get("response") or {}
    right_response = right.get("response") or {}
    left_body = str(left_response.get("body") or "")
    right_body = str(right_response.get("body") or "")
    return {
        "left_id": left_id,
        "right_id": right_id,
        "status_changed": left_response.get("status") != right_response.get("status"),
        "length_delta": int(right_response.get("length") or 0) - int(left_response.get("length") or 0),
        "time_delta_ms": float(right_response.get("duration_ms") or 0) - float(left_response.get("duration_ms") or 0),
        "body_hash_changed": hashlib.sha256(left_body.encode()).hexdigest() != hashlib.sha256(right_body.encode()).hexdigest(),
        "header_keys_added": sorted(set((right_response.get("headers") or {}).keys()) - set((left_response.get("headers") or {}).keys())),
        "header_keys_removed": sorted(set((left_response.get("headers") or {}).keys()) - set((right_response.get("headers") or {}).keys())),
    }


@router.post("/intruder/run")
async def run_intruder(request: IntruderPayload):
    await _validate_request(request)
    payloads = [str(item) for item in request.payloads if str(item).strip()][:request.max_requests]
    if not payloads:
        raise HTTPException(status_code=422, detail="Add at least one payload")
    if request.marker not in request.url and request.marker not in (request.body or ""):
        raise HTTPException(status_code=422, detail="Marker must appear in URL or body")

    results = []
    regex = re.compile(request.extract_regex) if request.extract_regex else None
    for index, payload in enumerate(payloads, start=1):
        mutated = ManualRequest(
            scan_id=request.scan_id,
            method=request.method,
            url=request.url.replace(request.marker, payload),
            headers=request.headers,
            body=(request.body or "").replace(request.marker, payload) if request.body is not None else None,
        )
        await _validate_request(mutated)
        try:
            response = await _send(mutated)
            body = str(response.get("body") or "")
            match = bool(request.match_text and request.match_text in body)
            extracted = regex.findall(body)[:5] if regex else []
            corpus = await _save_corpus_payload(_corpus_payload(mutated, response, note=f"Intruder payload #{index}: {payload}"))
            results.append({
                "payload": payload,
                "request_id": corpus["id"],
                "status": response["status"],
                "length": response["length"],
                "duration_ms": response["duration_ms"],
                "matched": match,
                "extracted": extracted,
            })
        except Exception as exc:
            results.append({"payload": payload, "error": str(exc)})
        if request.delay_ms:
            await asyncio.sleep(request.delay_ms / 1000)

    await store.push_log(request.scan_id, f"[INFO] Intruder completed {len(results)} payload attempts")
    return {"scan_id": request.scan_id, "results": results}


@router.post("/passive/{scan_id}/run")
async def run_passive_over_corpus(scan_id: str):
    scan = await store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    corpus = await store.list_corpus(scan_id)
    evidence = []
    for item in corpus:
        response = item.get("response") or {}
        evidence.append({
            "url": item.get("url"),
            "content_type": response.get("content_type") or item.get("content_type") or "",
            "response_headers": response.get("headers") or {},
            "response_excerpt": response.get("body") or item.get("response_excerpt") or "",
            "forms": [],
        })

    async def log(message: str) -> None:
        await store.push_log(scan_id, message)

    raw_findings = await passive.run(evidence, log)
    imported = 0
    for raw in raw_findings:
        finding = Finding(
            id=f"MAN-{uuid.uuid4().hex[:8].upper()}",
            scan_id=scan_id,
            title=str(raw.get("type", "manual")).replace("_", " ").title(),
            severity=Severity.info if raw.get("confidence") == "Informational" else Severity.medium,
            category="Passive Manual",
            target=str(raw.get("url") or ""),
            parameter=str(raw.get("param") or ""),
            confidence=raw.get("confidence", "Tentative"),
            status=FindingStatus.open,
            description="Detected from captured manual traffic.",
            recommendation="Review the captured evidence and confirm impact before remediation.",
            evidence=str(raw.get("evidence") or ""),
        )
        await store.add_finding(scan_id, finding)
        imported += 1
    await store.push_log(scan_id, f"[INFO] Manual passive scanner imported {imported} findings")
    return {"scan_id": scan_id, "imported": imported}


@router.post("/findings/{scan_id}/manual")
async def create_manual_finding(scan_id: str, payload: ManualFindingPayload):
    scan = await store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    request_record = await store.get_corpus_item(payload.request_id) if payload.request_id else None
    finding = Finding(
        id=f"MAN-{uuid.uuid4().hex[:8].upper()}",
        scan_id=scan_id,
        title=payload.title,
        severity=payload.severity,
        category=payload.vuln_type.replace("_", " ").title(),
        target=str((request_record or {}).get("url") or scan.config.target),
        parameter=payload.parameter,
        confidence="Confirmed" if payload.request_id else "Tentative",
        status=FindingStatus.open,
        description="Manual finding created from operator review.",
        recommendation=payload.recommendation,
        evidence=payload.evidence or json.dumps(request_record or {}, indent=2)[:4000],
    )
    await store.add_finding(scan_id, finding)
    await store.push_log(scan_id, f"[INFO] Manual finding created: {finding.id}")
    return finding.model_dump(mode="json")


@router.post("/decode")
async def decode_value(payload: DecodePayload):
    from urllib.parse import quote, unquote

    try:
        if payload.mode == "url-decode":
            output = unquote(payload.value)
        elif payload.mode == "url-encode":
            output = quote(payload.value)
        elif payload.mode == "base64-decode":
            output = base64.b64decode(payload.value).decode("utf-8", errors="replace")
        elif payload.mode == "base64-encode":
            output = base64.b64encode(payload.value.encode()).decode()
        elif payload.mode == "json-pretty":
            output = json.dumps(json.loads(payload.value), indent=2)
        else:
            output = hashlib.sha256(payload.value.encode()).hexdigest()
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Decode failed: {exc}") from exc
    return {"mode": payload.mode, "output": output}


@router.post("/proxy/start")
async def proxy_start(scan_id: str = "", host: str = "127.0.0.1", port: int = 8088):
    if scan_id:
        scan = await store.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if not scan.config.authorized:
            raise HTTPException(status_code=403, detail="The selected scan has no authorization confirmation")
    status = _capture_proxy.start(
        config=CaptureProxyConfig(host=host, port=port, scan_id=scan_id),
        save_payload=_save_corpus_payload,
        corpus_factory=_corpus_payload,
        scan_resolver=store.get_scan,
    )
    _proxy_state.update(status)
    return _proxy_state


@router.post("/proxy/stop")
async def proxy_stop():
    _proxy_state.update(_capture_proxy.stop())
    return _proxy_state


@router.get("/proxy/status")
async def proxy_status():
    _proxy_state.update(_capture_proxy.status())
    return _proxy_state


@router.get("/proxy/ca/status")
async def proxy_ca_status():
    return _ca_manager.status().to_dict()


@router.post("/proxy/ca/generate")
async def proxy_ca_generate(overwrite: bool = False):
    return _ca_manager.generate(overwrite=overwrite).to_dict()


@router.get("/proxy/ca/download")
async def proxy_ca_download():
    status = _ca_manager.status()
    if not status.generated:
        raise HTTPException(status_code=404, detail="Generate the Centrix CA before downloading it")
    return Response(
        content=_ca_manager.cert_path.read_bytes(),
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="centrix-local-ca.crt"'},
    )


@router.get("/proxy/ca/guide")
async def proxy_ca_guide():
    return {"steps": _ca_manager.install_guidance(), "status": _ca_manager.status().to_dict()}


@router.get("/proxy/ca/leaf/status")
async def proxy_ca_leaf_status(hostname: str):
    return _ca_manager.leaf_status(hostname).to_dict()


@router.post("/proxy/ca/leaf/generate")
async def proxy_ca_leaf_generate(hostname: str, overwrite: bool = False):
    return _ca_manager.generate_leaf_certificate(hostname, overwrite=overwrite).to_dict()


@router.post("/browser/open")
async def browser_open(url: str = "", scan_id: str = "", use_proxy: bool = True):
    result = await asyncio.to_thread(
        _browser.open,
        target_url=url,
        scan_id=scan_id,
        use_proxy=use_proxy,
        proxy_status=_proxy_state,
    )
    return result.to_dict()


@router.get("/browser/status")
async def browser_status():
    return (await asyncio.to_thread(_browser.status)).to_dict()


@router.post("/browser/close")
async def browser_close():
    return (await asyncio.to_thread(_browser.close)).to_dict()
