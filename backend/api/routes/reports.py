"""
Reports routes:
  POST /api/reports/generate     → generate report for a completed scan
  GET  /api/reports              → list all reports
  GET  /api/reports/{id}         → single report
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks
import db.store as store
from api.models import ReportConfig, Report

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/generate")
async def generate_report(cfg: ReportConfig, bg: BackgroundTasks):
    state = await store.get_scan(cfg.scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_id = f"RPT-{uuid.uuid4().hex[:8].upper()}"
    findings = await store.get_findings(cfg.scan_id)

    name = f"{cfg.report_type.capitalize()} Report — {cfg.target_scope or state.config.target}"
    report = Report(
        id=report_id,
        scan_id=cfg.scan_id,
        name=name,
        report_type=cfg.report_type,
        target=cfg.target_scope or state.config.target,
        generated_at=datetime.utcnow(),
        status="Ready",
        findings_count=len(findings),
        size=f"{max(1, len(findings) * 120) / 1024:.1f} KB",
        format=cfg.format,
    )

    # Build content based on format
    if cfg.format == "json":
        import json
        report.content = json.dumps(
            {
                "report_id": report_id,
                "scan_id": cfg.scan_id,
                "target": state.config.target,
                "generated_at": datetime.utcnow().isoformat(),
                "findings": [f.model_dump(mode="json") for f in findings],
                "summary": {
                    "total": len(findings),
                    "critical": sum(1 for f in findings if f.severity.value == "Critical"),
                    "high": sum(1 for f in findings if f.severity.value == "High"),
                    "medium": sum(1 for f in findings if f.severity.value == "Medium"),
                    "low": sum(1 for f in findings if f.severity.value == "Low"),
                },
            },
            indent=2,
        )
    elif cfg.format == "html":
        report.content = _build_html_report(report_id, state, findings)

    await store.save_report(report_id, report.model_dump(mode="json"))
    return report.model_dump(mode="json")


@router.get("")
async def list_reports():
    reports = await store.list_reports()
    return reports


@router.get("/{report_id}")
async def get_report(report_id: str):
    r = await store.get_report(report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return r


def _build_html_report(report_id: str, state, findings) -> str:
    rows = ""
    for f in findings:
        sev_color = {
            "Critical": "#e54646",
            "High": "#e07833",
            "Medium": "#c99a1a",
            "Low": "#3d82f6",
            "Info": "#64748b",
        }.get(f.severity.value, "#888")
        rows += f"""
        <tr>
          <td style="color:{sev_color};font-weight:700">{f.severity.value}</td>
          <td>{f.title}</td>
          <td><code>{f.target}</code></td>
          <td><code>{f.parameter}</code></td>
          <td>{f.confidence}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>VulnGuard Report {report_id}</title>
<style>
  body{{font-family:Inter,sans-serif;background:#090c14;color:#dce4f0;padding:2rem}}
  h1{{color:#5a57ff}}table{{width:100%;border-collapse:collapse;margin-top:1rem}}
  th{{background:#131c2a;padding:.6rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}}
  td{{padding:.6rem 1rem;border-bottom:1px solid #1a2030;font-size:.8rem}}
  code{{background:#131c2a;padding:.1rem .4rem;border-radius:3px;font-size:.75rem}}
</style></head>
<body>
<h1>VulnGuard Security Report</h1>
<p>Scan: {state.id} | Target: {state.config.target} | Generated: {datetime.utcnow().isoformat()}</p>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Parameter</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body></html>"""
