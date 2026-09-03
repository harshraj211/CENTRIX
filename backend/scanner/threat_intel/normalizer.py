"""
scanner/threat_intel/normalizer.py
------------------------------------
Parse and normalise raw advisory payloads from NVD, GHSA, and CISA-KEV
into a uniform AdvisoryRecord dataclass, then chunk long descriptions into
smaller pieces suitable for embedding.
"""
from __future__ import annotations

import re
import textwrap
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
CHUNK_SIZE = 600          # characters per chunk (safe for nomic-embed-text)
CHUNK_OVERLAP = 100       # character overlap between consecutive chunks


# ─────────────────────────────────────────────────────────────────────────────
# Canonical advisory record
# ─────────────────────────────────────────────────────────────────────────────

def infer_language(title: str = "", description: str = "", packages: Optional[List[str]] = None) -> str:
    """Infer target programming language/ecosystem from advisory metadata."""
    text = (f"{title} {description} " + " ".join(packages or [])).lower()
    if any(k in text for k in ["wordpress", "php", "composer", "drupal", "joomla"]):
        return "php"
    if any(k in text for k in ["pypi", "python", "django", "flask", "fastapi"]):
        return "python"
    if any(k in text for k in ["npm", "node", "javascript", "typescript", "express", "react", "vue", "next.js"]):
        return "javascript"
    if any(k in text for k in ["java", "maven", "gradle", "spring", "struts", "log4j"]):
        return "java"
    if any(k in text for k in ["ruby", "rubygems", "rails"]):
        return "ruby"
    if any(k in text for k in ["golang", "go:", "go.mod"]):
        return "go"
    if any(k in text for k in ["c++", "linux", "kernel", "glibc", "openssl"]):
        return "c/c++"
    return "unknown"


@dataclass
class AdvisoryRecord:
    """Normalised vulnerability advisory ready for vector-store ingestion."""

    cve_id: str                         # e.g. "CVE-2024-12345"
    source: str                         # "NVD" | "GHSA" | "CISA-KEV" | "exploitdb"
    title: str = ""
    description: str = ""
    published: str = ""
    last_modified: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""                  # critical / high / medium / low / info
    cwe: str = ""
    affected_packages: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cisa_kev: bool = False
    cisa_due_date: str = ""
    cisa_required_action: str = ""
    ghsa_id: str = ""
    language: str = "unknown"           # python / php / javascript / java / ruby / go / c/c++ / unknown
    raw_id: str = ""                    # source-native identifier

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_embed_text(self) -> str:
        """
        Produce a single dense text blob for embedding – blends all
        semantically useful fields so cosine search works well.
        """
        parts = [
            f"CVE: {self.cve_id}",
            f"Title: {self.title}",
            f"Severity: {self.severity.upper()} (CVSS {self.cvss_score})",
        ]
        if self.cwe:
            parts.append(f"CWE: {self.cwe}")
        if self.affected_packages:
            parts.append("Affected: " + ", ".join(self.affected_packages[:10]))
        if self.affected_versions:
            parts.append("Versions: " + ", ".join(self.affected_versions[:6]))
        parts.append(f"Description: {self.description[:800]}")
        if self.remediation:
            parts.append(f"Remediation: {self.remediation[:400]}")
        if self.cisa_kev:
            parts.append(f"CISA KEV Due: {self.cisa_due_date} — {self.cisa_required_action}")
        return "\n".join(parts)

    def chunk_text(self) -> List[str]:
        """
        Split the embed text into overlapping chunks of ≤ CHUNK_SIZE chars.
        Returns at least one chunk even for short records.
        """
        full = self.to_embed_text()
        if len(full) <= CHUNK_SIZE:
            return [full]
        chunks: List[str] = []
        start = 0
        while start < len(full):
            end = start + CHUNK_SIZE
            chunks.append(full[start:end])
            start = end - CHUNK_OVERLAP
        return chunks


# ─────────────────────────────────────────────────────────────────────────────
# NVD  (NVD CVE API 2.0 JSON item)
# ─────────────────────────────────────────────────────────────────────────────

def _float(v: Any) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _first_metric(metrics: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    for key in keys:
        items = metrics.get(key) or []
        if items:
            return items[0]
    return {}


def parse_nvd_item(item: Dict[str, Any]) -> AdvisoryRecord:
    """Parse a single CVE object from the NVD API 2.0 response."""
    cve = item.get("cve") or {}
    cve_id = (cve.get("id") or "").upper()

    # Description
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = str(d.get("value") or "")
            break

    # Published / Modified
    published = str(cve.get("published") or "")
    last_modified = str(cve.get("lastModified") or "")

    # CVSS
    metrics = cve.get("metrics") or {}
    metric = _first_metric(metrics, ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"])
    cvss_score = 0.0
    cvss_vector = ""
    severity = ""
    if metric:
        cvss_data = metric.get("cvssData") or {}
        cvss_score = _float(cvss_data.get("baseScore"))
        cvss_vector = str(cvss_data.get("vectorString") or "")
        severity = (
            cvss_data.get("baseSeverity") or metric.get("baseSeverity") or ""
        ).lower()

    # CWE
    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for wd in weakness.get("description") or []:
            v = str(wd.get("value") or "")
            if v.startswith("CWE-"):
                cwes.append(v)
    cwe = ", ".join(sorted(set(cwes)))

    # Affected packages + versions
    affected_packages: List[str] = []
    affected_versions: List[str] = []
    for config in (cve.get("configurations") or []):
        for node in (config.get("nodes") or []):
            for cpe_match in (node.get("cpeMatch") or []):
                criteria = str(cpe_match.get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    pkg = ":".join(parts[3:5])
                    if pkg not in affected_packages:
                        affected_packages.append(pkg)
                ver_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                ver_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                if ver_start or ver_end:
                    affected_versions.append(f"{ver_start or '*'}–{ver_end or '*'}")

    # References
    refs = [str(r.get("url") or "") for r in (cve.get("references") or []) if r.get("url")]

    # Title: first 120 chars of description as fallback
    title = desc[:120].rstrip() + ("…" if len(desc) > 120 else "")
    lang = infer_language(title, desc, affected_packages)

    return AdvisoryRecord(
        cve_id=cve_id,
        source="NVD",
        title=title,
        description=desc,
        published=published,
        last_modified=last_modified,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        cwe=cwe,
        affected_packages=affected_packages[:20],
        affected_versions=affected_versions[:10],
        references=refs[:15],
        language=lang,
        raw_id=cve_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV  (single vuln dict from the KEV JSON catalog)
# ─────────────────────────────────────────────────────────────────────────────

def parse_cisa_kev_item(item: Dict[str, Any]) -> AdvisoryRecord:
    cve_id = (item.get("cveID") or "").upper()
    cvss_score = _float(item.get("cvssScore"))
    severity = "critical" if cvss_score >= 9.0 else (
        "high" if cvss_score >= 7.0 else (
            "medium" if cvss_score >= 4.0 else "low"
        )
    )
    vendor = str(item.get("vendorProject") or "")
    product = str(item.get("product") or "")
    vuln_name = str(item.get("vulnerabilityName") or "")
    desc = str(item.get("shortDescription") or "")
    remediation = str(item.get("requiredAction") or "")
    title = vuln_name or f"{vendor} {product} vulnerability"
    packages = [f"{vendor}:{product}"] if vendor and product else []
    lang = infer_language(title, desc, packages)

    return AdvisoryRecord(
        cve_id=cve_id,
        source="CISA-KEV",
        title=title,
        description=desc,
        published=str(item.get("dateAdded") or ""),
        cvss_score=cvss_score,
        severity=severity,
        affected_packages=packages,
        remediation=remediation,
        cisa_kev=True,
        cisa_due_date=str(item.get("dueDate") or ""),
        cisa_required_action=remediation,
        language=lang,
        raw_id=cve_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GHSA  (GitHub GraphQL SecurityAdvisory node)
# ─────────────────────────────────────────────────────────────────────────────

def parse_ghsa_node(node: Dict[str, Any]) -> Optional[AdvisoryRecord]:
    """
    Parse a GitHub Security Advisory GraphQL node.
    Returns None if the record has no identifiers.
    """
    ghsa_id = str(node.get("ghsaId") or "")
    identifiers = node.get("identifiers") or []
    cve_id = ""
    for ident in identifiers:
        if ident.get("type") == "CVE":
            cve_id = str(ident.get("value") or "").upper()
            break
    if not cve_id and not ghsa_id:
        return None

    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "LOW": "low",
    }
    severity = severity_map.get(str(node.get("severity") or "").upper(), "info")
    cvss_score = _float((node.get("cvss") or {}).get("score"))
    cvss_vector = str((node.get("cvss") or {}).get("vectorString") or "")

    desc = str(node.get("description") or "")
    summary = str(node.get("summary") or "")

    # Affected packages
    affected_packages: List[str] = []
    affected_versions: List[str] = []
    for vuln in (node.get("vulnerabilities") or {}).get("nodes") or []:
        pkg = (vuln.get("package") or {}).get("name") or ""
        ecosystem = (vuln.get("package") or {}).get("ecosystem") or ""
        if pkg:
            label = f"{ecosystem.lower()}:{pkg}" if ecosystem else pkg
            if label not in affected_packages:
                affected_packages.append(label)
        ver_range = str(vuln.get("vulnerableVersionRange") or "")
        if ver_range and ver_range not in affected_versions:
            affected_versions.append(ver_range)
        # Patched version
        fp_dict = vuln.get("firstPatchedVersion") or {}
        first_patch = fp_dict.get("identifier") if isinstance(fp_dict, dict) else ""
        if first_patch:
            affected_versions.append(f"fixed in {first_patch}")

    refs = [r.get("url", "") for r in (node.get("references") or []) if r.get("url")]
    cwes = [c.get("cweId", "") for c in (node.get("cwes") or {}).get("nodes") or [] if c.get("cweId")]
    title = summary or (desc[:120].rstrip())
    lang = infer_language(title, desc, affected_packages)

    return AdvisoryRecord(
        cve_id=cve_id or ghsa_id,
        source="GHSA",
        title=title,
        description=desc,
        published=str(node.get("publishedAt") or ""),
        last_modified=str(node.get("updatedAt") or ""),
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        severity=severity,
        cwe=", ".join(cwes),
        affected_packages=affected_packages[:20],
        affected_versions=affected_versions[:10],
        references=refs[:15],
        ghsa_id=ghsa_id,
        language=lang,
        raw_id=ghsa_id or cve_id,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Dependency manifest → package list
# ─────────────────────────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> List[Dict[str, str]]:
    """Return list of {name, version_spec} dicts from a requirements.txt."""
    results: List[Dict[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # strip extras, environment markers
        line = re.sub(r"\[.*?\]", "", line)
        line = re.split(r";", line)[0].strip()
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~^].*)?$", line)
        if match:
            results.append({
                "name": match.group(1).lower(),
                "version_spec": (match.group(2) or "").strip(),
                "ecosystem": "pypi",
            })
    return results


def parse_package_json(data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return flat list of {name, version_spec, ecosystem} from package.json."""
    results: List[Dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            results.append({
                "name": name.lower(),
                "version_spec": str(spec),
                "ecosystem": "npm",
            })
    return results
