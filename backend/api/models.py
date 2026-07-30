"""Pydantic v2 models shared across API and scanner."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────
class ScanProfile(str, Enum):
    quick = "quick"
    full = "full"
    api = "api"
    custom = "custom"


class SafetyLevel(str, Enum):
    passive = "passive"
    standard = "standard"
    aggressive = "aggressive"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    paused = "paused"
    completed = "completed"
    stopped = "stopped"
    error = "error"


class ScanStage(str, Enum):
    validate = "validate"
    discover = "discover"
    crawl = "crawl"
    probe = "probe"
    analyze = "analyze"
    report = "report"
    done = "done"


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


class FindingStatus(str, Enum):
    open = "Open"
    in_review = "In Review"
    fixed = "Fixed"
    accepted = "Accepted"


# ── Scan Configuration ────────────────────────────────────────────
class ScanConfig(BaseModel):
    target: str = Field(..., description="Primary target URL")
    scope: list[str] = Field(default_factory=list, description="Scope rules / URL patterns")
    profile: ScanProfile = ScanProfile.full
    safety: SafetyLevel = SafetyLevel.standard
    depth: int = Field(default=3, ge=1, le=10)
    timeout: int = Field(default=30, ge=5, le=120)
    concurrency: int = Field(default=25, ge=1, le=100)
    auth_token: Optional[str] = None
    label: Optional[str] = None
    environment: str = "Production"


# ── Scan State ────────────────────────────────────────────────────
class ScanState(BaseModel):
    id: str
    config: ScanConfig
    status: ScanStatus = ScanStatus.pending
    stage: ScanStage = ScanStage.validate
    progress: int = 0            # 0-100
    findings_count: int = 0
    requests_sent: int = 0
    urls_discovered: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_msg: Optional[str] = None
    duration_s: Optional[float] = None


# ── Finding ───────────────────────────────────────────────────────
class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: Severity
    category: str
    target: str
    parameter: str
    confidence: Literal["Confirmed", "Tentative", "Informational"] = "Tentative"
    status: FindingStatus = FindingStatus.open
    found_at: datetime = Field(default_factory=datetime.utcnow)
    description: str
    recommendation: str
    evidence: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None


# ── Report ────────────────────────────────────────────────────────
class ReportConfig(BaseModel):
    scan_id: str
    format: Literal["json", "html", "pdf"] = "json"
    report_type: Literal["technical", "executive", "compliance"] = "technical"
    target_scope: Optional[str] = None


class Report(BaseModel):
    id: str
    scan_id: str
    name: str
    report_type: str
    target: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    status: Literal["Pending", "Ready"] = "Pending"
    findings_count: int = 0
    size: str = "—"
    format: str = "json"
    content: Optional[str] = None   # rendered HTML/JSON string


# ── API Responses ──────────────────────────────────────────────────
class StartScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    stage: ScanStage
    progress: int
    findings_count: int
    requests_sent: int
    urls_discovered: int
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    duration_s: Optional[float]
