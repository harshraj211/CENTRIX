"""
scanner/threat_intel/rag_engine.py
------------------------------------
Retrieval-Augmented Generation engine for vulnerability analysis.

Given a code snippet or dependency manifest, the engine:
  1. Extracts semantic context (package names, CVE mentions, tech stack).
  2. Embeds the query via Ollama nomic-embed-text.
  3. Retrieves the top-K most relevant advisories from ChromaDB.
  4. Builds a structured prompt with retrieved context.
  5. Calls the local Ollama chat model for a comprehensive security analysis.
  6. Returns a structured AnalysisResult.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .config import cfg
from .normalizer import (
    parse_package_json,
    parse_requirements_txt,
    AdvisoryRecord,
)
from .ollama_client import OllamaClient, SyncOllamaClient
from .vector_store import ThreatIntelVectorStore

logger = logging.getLogger("wraith.threat_intel.rag_engine")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# ─────────────────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RetrievedAdvisory:
    """A single advisory retrieved from the vector store."""
    cve_id: str
    source: str
    title: str
    severity: str
    cvss_score: float
    cwe: str
    affected_packages: List[str]
    affected_versions: List[str]
    remediation: str
    cisa_kev: bool
    similarity: float
    chunk_text: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Full RAG analysis result."""
    query_type: str                                  # "code" | "manifest" | "cve" | "freeform"
    query_summary: str                               # brief description of what was analysed
    retrieved_advisories: List[RetrievedAdvisory] = field(default_factory=list)
    llm_analysis: str = ""                          # full LLM response
    risk_level: str = "unknown"                     # critical / high / medium / low / info
    matched_cves: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    model_used: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an elite security engineer with deep expertise in both defensive and offensive cybersecurity.

Your goal is to produce a comprehensive, actionable analysis of a given vulnerability. Use the retrieved context (CVE data, exploit code, remediation guides) to answer accurately. If the context is insufficient, say so clearly – do not invent facts.

For every response, adhere to this **strict output structure**:

1. **Description** – 2‑3 sentences explaining the vulnerability and its root cause.
2. **Impact** – What an attacker can achieve (data theft, RCE, etc.) and CVSS score if available.
3. **Affected Components** – Software, versions, configurations.
4. **Remediation** – Concrete steps (code fixes, configuration changes, patching).
5. **Exploitation Payload** (if offensive context exists) – Provide a working payload tailored to the target parameters. If no exploit code is retrieved, state "No specific payload available – use generic injection techniques."
6. **Attack Chain** – A numbered list of steps an attacker would follow to exploit this, including any pre‑ and post‑exploitation actions.
7. **Confidence Score** – A number from 1–10 indicating how certain you are of your analysis (10 = fully certain, based on retrieved evidence).
8. **References** – List the CVE ID(s) and any source IDs (e.g., EDB‑xxxx) from the retrieved chunks.

Format your response as a JSON object with keys: description, impact, affected_components, remediation, payload, attack_chain, confidence, references."""


# ─────────────────────────────────────────────────────────────────────────────
# Query context builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_context_block(advisories: List[RetrievedAdvisory]) -> str:
    if not advisories:
        return "No matching advisories found in the local knowledge base."

    lines = ["## Retrieved Vulnerability Context\n"]
    for i, adv in enumerate(advisories, 1):
        kev_tag = " 🔴 CISA KEV" if adv.cisa_kev else ""
        lines.append(
            f"### [{i}] {adv.cve_id} — {adv.title}{kev_tag}\n"
            f"- **Severity**: {adv.severity.upper()} (CVSS {adv.cvss_score})\n"
            f"- **CWE**: {adv.cwe or 'N/A'}\n"
            f"- **Affected**: {', '.join(adv.affected_packages[:5]) or 'N/A'}\n"
            f"- **Versions**: {', '.join(adv.affected_versions[:3]) or 'N/A'}\n"
            f"- **Remediation**: {adv.remediation or 'See official advisory'}\n"
            f"- **Source**: {adv.source}  (relevance: {adv.similarity:.2%})\n"
            f"- **Details**: {adv.chunk_text[:300]}…\n"
        )
    return "\n".join(lines)


def _build_prompt(
    query: str,
    context: str,
    query_type: str,
    packages: Optional[List[Dict[str, str]]] = None,
) -> str:
    pkg_section = ""
    if packages:
        pkg_lines = "\n".join(
            f"  - {p['name']} {p.get('version_spec', '')} ({p.get('ecosystem', '')})"
            for p in packages[:30]
        )
        pkg_section = f"\n## Dependency Manifest Packages\n{pkg_lines}\n"

    type_instruction = {
        "code": "Analyse the following SOURCE CODE for security vulnerabilities.",
        "manifest": "Analyse the following DEPENDENCY MANIFEST for known vulnerable packages.",
        "cve": "Provide a detailed analysis of the following CVE(s).",
        "freeform": "Answer the following security question using the context below.",
    }.get(query_type, "Analyse the following for security vulnerabilities.")

    return (
        f"{type_instruction}\n\n"
        f"## Input\n```\n{query[:3000]}\n```\n"
        f"{pkg_section}\n"
        f"{context}\n\n"
        "## Required Output\n"
        "1. **Overall Risk Level**: (CRITICAL/HIGH/MEDIUM/LOW/INFO)\n"
        "2. **Matched CVEs**: List any CVEs that directly apply to this input.\n"
        "3. **Security Findings**: Detailed findings with CVE references.\n"
        "4. **Remediation Steps**: Specific, actionable fix recommendations.\n"
        "5. **Additional Notes**: Any supplementary security observations.\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Risk level extractor
# ─────────────────────────────────────────────────────────────────────────────

def _extract_risk_level(text: str, advisories: List[RetrievedAdvisory]) -> str:
    # Try to extract from LLM output first
    pattern = re.search(
        r"(?:overall risk level|risk)[:\s*]+\*{0,2}(CRITICAL|HIGH|MEDIUM|LOW|INFO)\*{0,2}",
        text,
        re.IGNORECASE,
    )
    if pattern:
        return pattern.group(1).lower()
    # Fall back to highest CVSS among retrieved advisories
    if advisories:
        max_cvss = max(a.cvss_score for a in advisories)
        if max_cvss >= 9.0:
            return "critical"
        if max_cvss >= 7.0:
            return "high"
        if max_cvss >= 4.0:
            return "medium"
        if max_cvss > 0:
            return "low"
    return "info"


def _extract_remediation_steps(text: str) -> List[str]:
    """Pull out numbered remediation lines from LLM output."""
    steps: List[str] = []
    in_remediation = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"remediation steps?", stripped, re.IGNORECASE):
            in_remediation = True
            continue
        if in_remediation:
            if re.match(r"^#{1,4}\s", stripped) and not re.search(r"remediation", stripped, re.IGNORECASE):
                in_remediation = False
                continue
            if stripped and (stripped[0].isdigit() or stripped.startswith("-")):
                steps.append(re.sub(r"^[\d\.\-\*]+\s*", "", stripped))
    return steps[:10]


# ─────────────────────────────────────────────────────────────────────────────
# Main RAG engine
# ─────────────────────────────────────────────────────────────────────────────

class RagEngine:
    """
    Retrieval-Augmented Generation engine for local threat intelligence.

    Usage (async)
    -------------
    engine = RagEngine()
    result = await engine.analyse_code("import pickle; pickle.loads(data)")
    result = await engine.analyse_manifest("flask==0.12.0\nrequests==2.18.4")
    result = await engine.analyse_cve("CVE-2024-1234")

    Usage (sync)
    ------------
    engine = RagEngine()
    result = engine.analyse_code_sync("...")
    """

    def __init__(
        self,
        store: Optional[ThreatIntelVectorStore] = None,
        ollama: Optional[OllamaClient] = None,
    ) -> None:
        self._store = store or ThreatIntelVectorStore()
        self._ollama = ollama or OllamaClient()

    # ── Core retrieval ────────────────────────────────────────────────────────

    async def _retrieve(
        self,
        query_text: str,
        top_k: Optional[int] = None,
        where: Optional[Dict[str, Any]] = None,
        language: Optional[str] = None,
    ) -> List[RetrievedAdvisory]:
        k = top_k or cfg.rag_top_k
        embedding = await self._ollama.embed(query_text)
        if not embedding:
            logger.warning("Failed to embed query; retrieval will be empty.")
            return []

        query_where = where
        if not query_where and language and language.lower() != "unknown":
            query_where = {"language": language.lower()}

        hits = self._store.query(
            query_embedding=embedding,
            top_k=k,
            min_similarity=cfg.rag_min_relevance,
            where=query_where,
        )

        # Fallback if language filter yielded no hits
        if not hits and query_where and "language" in query_where:
            logger.debug("No hits with language filter '%s'; falling back to unfiltered query.", language)
            hits = self._store.query(
                query_embedding=embedding,
                top_k=k,
                min_similarity=cfg.rag_min_relevance,
                where=None,
            )

        results: List[RetrievedAdvisory] = []
        for similarity, meta in hits:
            results.append(
                RetrievedAdvisory(
                    cve_id=meta.get("cve_id", ""),
                    source=meta.get("source", ""),
                    title=meta.get("title", ""),
                    severity=meta.get("severity", ""),
                    cvss_score=float(meta.get("cvss_score", 0)),
                    cwe=meta.get("cwe", ""),
                    affected_packages=meta.get("affected_packages", []),
                    affected_versions=meta.get("affected_versions", []),
                    remediation=meta.get("remediation", ""),
                    cisa_kev=bool(meta.get("cisa_kev", False)),
                    similarity=similarity,
                    chunk_text=meta.get("_chunk_text", "")[:500],  # Truncate chunk text to 500 chars for latency optimization
                )
            )
        return results

    # ── Core generation ───────────────────────────────────────────────────────

    async def _generate(
        self,
        query: str,
        query_type: str,
        advisories: List[RetrievedAdvisory],
        packages: Optional[List[Dict[str, str]]] = None,
    ) -> Tuple[str, str]:
        """Returns (llm_text, model_name)."""
        context = _build_context_block(advisories)
        prompt = _build_prompt(query, context, query_type, packages)

        result = await self._ollama.chat(prompt, system=SYSTEM_PROMPT)
        return result.get("content", ""), result.get("model", cfg.ollama_chat_model)

    # ── Public API (async) ────────────────────────────────────────────────────

    async def analyse_code(
        self,
        code: str,
        language: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> AnalysisResult:
        """Analyse a source code snippet for known vulnerabilities with language filtering."""
        query_text = f"Security vulnerabilities in {language or 'source'} code:\n{code[:2000]}"
        advisories = await self._retrieve(query_text, top_k=top_k, language=language)
        llm_text, model = await self._generate(code, "code", advisories)

        cves_in_output = sorted({c.upper() for c in CVE_RE.findall(llm_text)})
        return AnalysisResult(
            query_type="code",
            query_summary=f"Code analysis ({language or 'unknown'}, {len(code)} chars)",
            retrieved_advisories=advisories,
            llm_analysis=llm_text,
            risk_level=_extract_risk_level(llm_text, advisories),
            matched_cves=cves_in_output,
            remediation_steps=_extract_remediation_steps(llm_text),
            model_used=model,
        )

    async def analyse_manifest(
        self,
        content: str,
        manifest_type: str = "auto",
        top_k: Optional[int] = None,
    ) -> AnalysisResult:
        """
        Analyse a dependency manifest (requirements.txt or package.json).

        manifest_type : "requirements" | "package.json" | "auto"
        """
        packages: List[Dict[str, str]] = []
        detected_type = manifest_type

        if manifest_type == "auto":
            # Heuristic detection
            stripped = content.strip()
            if stripped.startswith("{"):
                detected_type = "package.json"
            else:
                detected_type = "requirements"

        if detected_type == "package.json":
            try:
                packages = parse_package_json(json.loads(content))
            except Exception:
                packages = []
        else:
            packages = parse_requirements_txt(content)

        # Build a rich semantic query from extracted packages
        pkg_names = [p["name"] for p in packages[:40]]
        query_text = (
            "Security vulnerabilities in packages: " + ", ".join(pkg_names) + "\n"
            "Ecosystem: " + (packages[0].get("ecosystem", "unknown") if packages else "unknown")
        )

        advisories = await self._retrieve(query_text, top_k=top_k)
        llm_text, model = await self._generate(content, "manifest", advisories, packages=packages)

        cves_in_output = sorted({c.upper() for c in CVE_RE.findall(llm_text)})
        return AnalysisResult(
            query_type="manifest",
            query_summary=f"Manifest analysis ({detected_type}, {len(packages)} packages)",
            retrieved_advisories=advisories,
            llm_analysis=llm_text,
            risk_level=_extract_risk_level(llm_text, advisories),
            matched_cves=cves_in_output,
            remediation_steps=_extract_remediation_steps(llm_text),
            model_used=model,
        )

    async def analyse_cve(
        self,
        cve_ids: str | List[str],
        top_k: Optional[int] = None,
    ) -> AnalysisResult:
        """Deep-dive analysis of one or more CVE IDs."""
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        query_text = "Detailed analysis of CVEs: " + ", ".join(cve_ids)
        advisories = await self._retrieve(query_text, top_k=top_k)
        llm_text, model = await self._generate(", ".join(cve_ids), "cve", advisories)

        return AnalysisResult(
            query_type="cve",
            query_summary=f"CVE analysis: {', '.join(cve_ids)}",
            retrieved_advisories=advisories,
            llm_analysis=llm_text,
            risk_level=_extract_risk_level(llm_text, advisories),
            matched_cves=sorted({c.upper() for c in CVE_RE.findall(llm_text + " ".join(cve_ids))}),
            remediation_steps=_extract_remediation_steps(llm_text),
            model_used=model,
        )

    async def freeform_query(
        self,
        question: str,
        top_k: Optional[int] = None,
    ) -> AnalysisResult:
        """Answer a natural-language security question using the RAG knowledge base."""
        advisories = await self._retrieve(question, top_k=top_k)
        llm_text, model = await self._generate(question, "freeform", advisories)

        return AnalysisResult(
            query_type="freeform",
            query_summary=question[:120],
            retrieved_advisories=advisories,
            llm_analysis=llm_text,
            risk_level=_extract_risk_level(llm_text, advisories),
            matched_cves=sorted({c.upper() for c in CVE_RE.findall(llm_text)}),
            remediation_steps=_extract_remediation_steps(llm_text),
            model_used=model,
        )

    def _parse_response(self, content: str) -> Dict[str, Any]:
        """Safely parse JSON output from the LLM, handling optional markdown code blocks."""
        cleaned = content.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON; returning raw text object.")
            return {
                "description": content,
                "impact": "N/A",
                "affected_components": "N/A",
                "remediation": "N/A",
                "payload": "No specific payload available – use generic injection techniques.",
                "attack_chain": [],
                "confidence": 5,
                "references": [],
                "raw": content,
            }

    async def analyse_vulnerability(self, vuln_data: Dict[str, Any], top_k: int = 2) -> Dict[str, Any]:
        """
        Analyse a detected vulnerability record against ChromaDB knowledge store using system instructions.
        Returns a structured JSON dictionary.
        """
        query_text = (
            f"Vulnerability: {vuln_data.get('type', '')} {vuln_data.get('parameter', '')} "
            f"{vuln_data.get('library', '')} {vuln_data.get('snippet', '')}"
        )
        advisories = await self._retrieve(query_text, top_k=top_k)
        retrieved_chunks = [a.chunk_text for a in advisories if a.chunk_text]

        context_str = "\n".join(retrieved_chunks) if retrieved_chunks else "No specific context retrieved."

        user_prompt = f"""**Vulnerability Detected:**
- Type: {vuln_data.get('type', 'N/A')}
- Target URL: {vuln_data.get('url', 'N/A')}
- Parameter: {vuln_data.get('parameter', 'N/A')}
- Request/Response snippets: {vuln_data.get('snippet', 'N/A')}
- Detected library/version: {vuln_data.get('library', 'Unknown')}

**Retrieved Context from Knowledge Base:**
{context_str}

**Task:**
Generate a complete analysis following the system instructions. If the context contains exploit code, include a realistic payload and attack chain. If not, provide a defensive analysis only."""

        result = await self._ollama.chat(user_prompt, system=SYSTEM_PROMPT)
        raw_content = result.get("content", "")
        parsed = self._parse_response(raw_content)
        parsed["retrieved_advisories"] = [a.to_dict() for a in advisories]
        return parsed

    # ── Sync wrappers ─────────────────────────────────────────────────────────

    def _run(self, coro: Any) -> Any:
        import asyncio, concurrent.futures
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, coro).result()
            return loop.run_until_complete(coro)
        except RuntimeError:
            return asyncio.run(coro)

    def analyse_code_sync(self, code: str, **kw: Any) -> AnalysisResult:
        return self._run(self.analyse_code(code, **kw))

    def analyse_manifest_sync(self, content: str, **kw: Any) -> AnalysisResult:
        return self._run(self.analyse_manifest(content, **kw))

    def analyse_cve_sync(self, cve_ids: Any, **kw: Any) -> AnalysisResult:
        return self._run(self.analyse_cve(cve_ids, **kw))

    def freeform_query_sync(self, question: str, **kw: Any) -> AnalysisResult:
        return self._run(self.freeform_query(question, **kw))

    def analyse_vulnerability_sync(self, vuln_data: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
        return self._run(self.analyse_vulnerability(vuln_data, **kw))

    # ── Store pass-through ────────────────────────────────────────────────────

    def store_stats(self) -> Dict[str, Any]:
        return self._store.stats()

