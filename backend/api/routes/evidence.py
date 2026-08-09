import json
from datetime import datetime
from fastapi import APIRouter, Query, HTTPException, Response
import db.store as store
router = APIRouter(prefix="/api/evidence", tags=["evidence"])
@router.get("")
async def list_evidence(scan_id: str | None = Query(default=None)):
    return [item.model_dump(mode="json") for item in await store.get_evidence(scan_id)]


@router.get("/bundle/{finding_id}")
async def finding_evidence_bundle(finding_id: str):
    finding = await store.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    evidence = await store.get_evidence(finding.scan_id)
    corpus = await store.list_corpus(finding.scan_id)
    related_evidence = [
        item.model_dump(mode="json") for item in evidence
        if item.url == finding.target or finding.target in item.url or item.url in finding.target
    ]
    related_corpus = [
        item for item in corpus
        if item.get("url") == finding.target or finding.target in item.get("url", "") or item.get("url", "") in finding.target
    ][:20]
    payload = {
        "bundle_id": f"EVB-{finding.id}",
        "scanner": "Centrix DAST",
        "generated_at": datetime.utcnow().isoformat(),
        "finding": finding.model_dump(mode="json"),
        "evidence": related_evidence,
        "corpus": related_corpus,
        "operator_note": "Evidence bundle generated for proof/retest handoff.",
    }
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="EVB-{finding.id}.json"'},
    )
