"""
Findings routes:
  GET /api/findings              → all findings (optionally filter by scan_id)
  GET /api/findings/{id}         → single finding O(1) after flattening
"""
from __future__ import annotations

from fastapi import APIRouter, Query, HTTPException
import db.store as store
from api.models import Finding

router = APIRouter(prefix="/api/findings", tags=["findings"])

# O(1) finding lookup built lazily — rebuilt when new findings arrive
_finding_index: dict[str, Finding] = {}


def _index_finding(f: Finding):
    _finding_index[f.id] = f


@router.get("")
async def list_findings(scan_id: str | None = Query(default=None)):
    if scan_id:
        findings = await store.get_findings(scan_id)
    else:
        findings = await store.get_all_findings()

    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "target": f.target,
            "parameter": f.parameter,
            "confidence": f.confidence,
            "status": f.status,
            "found_at": f.found_at,
            "cwe": f.cwe,
            "cvss": f.cvss,
        }
        for f in findings
    ]


@router.get("/{finding_id}")
async def get_finding(finding_id: str):
    # Try O(1) index first
    f = _finding_index.get(finding_id)
    if f:
        return f.model_dump()

    # Fall back: linear scan once (then index it)
    all_findings = await store.get_all_findings()
    for finding in all_findings:
        _finding_index[finding.id] = finding
        if finding.id == finding_id:
            return finding.model_dump()

    raise HTTPException(status_code=404, detail="Finding not found")
