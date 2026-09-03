"""
scanner/threat_intel/routes.py
--------------------------------
Flask Blueprint exposing the Wraith Threat Intelligence RAG pipeline as a
REST API.

Endpoints
---------
POST /api/threat-intel/analyse/code
POST /api/threat-intel/analyse/manifest
POST /api/threat-intel/analyse/cve
POST /api/threat-intel/query
POST /api/threat-intel/sync          (trigger manual sync)
GET  /api/threat-intel/status        (store stats + scheduler status)
GET  /api/threat-intel/health        (Ollama connectivity check)
DELETE /api/threat-intel/store/reset (danger: wipe the vector store)
"""
from __future__ import annotations

import asyncio
import logging
import threading
from functools import wraps
from typing import Any, Callable, Dict

from flask import Blueprint, Response, jsonify, request, stream_with_context

from .config import cfg
from .ollama_client import OllamaClient, SyncOllamaClient
from .rag_engine import RagEngine
from .sync_worker import get_scheduler, run_sync, start_scheduler
from .vector_store import ThreatIntelVectorStore

logger = logging.getLogger("wraith.threat_intel.routes")

threat_intel_bp = Blueprint("threat_intel", __name__, url_prefix="/api/threat-intel")

# ─────────────────────────────────────────────────────────────────────────────
# Lazy singletons (initialised on first request)
# ─────────────────────────────────────────────────────────────────────────────

_engine: RagEngine | None = None
_store: ThreatIntelVectorStore | None = None
_ollama_sync: SyncOllamaClient | None = None
_lock = threading.Lock()


def _get_engine() -> RagEngine:
    global _engine, _store, _ollama_sync
    with _lock:
        if _engine is None:
            _store = ThreatIntelVectorStore()
            _engine = RagEngine(store=_store)
            _ollama_sync = SyncOllamaClient()
    return _engine


def _get_store() -> ThreatIntelVectorStore:
    _get_engine()
    return _store  # type: ignore[return-value]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _json_error(message: str, status: int = 400) -> Response:
    return jsonify({"error": message, "status": status}), status  # type: ignore[return-value]


def _run_async(coro: Any) -> Any:
    """Run async coroutine safely regardless of event-loop state."""
    import concurrent.futures
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def require_json(f: Callable) -> Callable:
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not request.is_json:
            return _json_error("Content-Type must be application/json")
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@threat_intel_bp.route("/health", methods=["GET"])
def health() -> Response:
    """Quick Ollama + ChromaDB connectivity check."""
    try:
        ollama_ok = _run_async(OllamaClient().health())
        models = _run_async(OllamaClient().list_models()) if ollama_ok else []
        store_ok = _get_store().count() >= 0
        return jsonify({
            "ollama": {"reachable": ollama_ok, "models": models},
            "vector_store": {"ok": store_ok},
            "chat_model": cfg.ollama_chat_model,
            "embed_model": cfg.ollama_embed_model,
        })
    except Exception as exc:
        return _json_error(str(exc), 503)


@threat_intel_bp.route("/status", methods=["GET"])
def status() -> Response:
    """Return vector store statistics and scheduler status."""
    try:
        stats = _get_store().stats()
        scheduler = get_scheduler()
        jobs = [
            {
                "id": j.id,
                "name": j.name,
                "next_run": str(j.next_run_time) if j.next_run_time else None,
            }
            for j in scheduler.get_jobs()
        ]
        return jsonify({
            "store": stats,
            "scheduler": {
                "running": scheduler.running,
                "jobs": jobs,
                "sync_interval_hours": cfg.sync_interval_hours,
            },
        })
    except Exception as exc:
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/analyse/code", methods=["POST"])
@require_json
def analyse_code() -> Response:
    """
    Analyse source code for known vulnerabilities.

    Body
    ----
    {
      "code":     "<source code string>",
      "language": "python"   // optional
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    code = str(body.get("code") or "").strip()
    if not code:
        return _json_error("`code` field is required")

    language = str(body.get("language") or "")
    top_k = int(body.get("top_k") or cfg.rag_top_k)

    try:
        engine = _get_engine()
        result = _run_async(engine.analyse_code(code, language=language or None, top_k=top_k))
        return jsonify(result.to_dict())
    except Exception as exc:
        logger.exception("analyse_code failed")
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/analyse/manifest", methods=["POST"])
@require_json
def analyse_manifest() -> Response:
    """
    Analyse a dependency manifest for vulnerable packages.

    Body
    ----
    {
      "content":       "<manifest text>",
      "manifest_type": "requirements"   // or "package.json", "auto"
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    content = str(body.get("content") or "").strip()
    if not content:
        return _json_error("`content` field is required")

    manifest_type = str(body.get("manifest_type") or "auto")
    top_k = int(body.get("top_k") or cfg.rag_top_k)

    try:
        engine = _get_engine()
        result = _run_async(engine.analyse_manifest(content, manifest_type=manifest_type, top_k=top_k))
        return jsonify(result.to_dict())
    except Exception as exc:
        logger.exception("analyse_manifest failed")
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/analyse/cve", methods=["POST"])
@require_json
def analyse_cve() -> Response:
    """
    Deep analysis of specific CVE IDs.

    Body
    ----
    {
      "cve_ids": ["CVE-2024-1234", "CVE-2023-5678"]
      // or "cve_ids": "CVE-2024-1234"
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    cve_ids = body.get("cve_ids") or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    if not cve_ids:
        return _json_error("`cve_ids` field is required")

    top_k = int(body.get("top_k") or cfg.rag_top_k)

    try:
        engine = _get_engine()
        result = _run_async(engine.analyse_cve(cve_ids, top_k=top_k))
        return jsonify(result.to_dict())
    except Exception as exc:
        logger.exception("analyse_cve failed")
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/query", methods=["POST"])
@require_json
def freeform_query() -> Response:
    """
    Natural-language security question answered with RAG context.

    Body
    ----
    { "question": "What vulnerabilities affect Log4j?" }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    question = str(body.get("question") or "").strip()
    if not question:
        return _json_error("`question` field is required")

    top_k = int(body.get("top_k") or cfg.rag_top_k)

    try:
        engine = _get_engine()
        result = _run_async(engine.freeform_query(question, top_k=top_k))
        return jsonify(result.to_dict())
    except Exception as exc:
        logger.exception("freeform_query failed")
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/analyse/vulnerability", methods=["POST"])
@require_json
def analyse_vulnerability() -> Response:
    """
    Analyse a detected vulnerability record against ChromaDB RAG context.
    Returns structured JSON (description, impact, affected_components, remediation, payload, attack_chain, confidence, references).

    Body
    ----
    {
      "type": "SQL Injection",
      "url": "http://example.com/api/users",
      "parameter": "id",
      "snippet": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
      "library": "WordPress 5.8",
      "top_k": 2
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    top_k = int(body.get("top_k") or 2)

    try:
        engine = _get_engine()
        result = _run_async(engine.analyse_vulnerability(body, top_k=top_k))
        return jsonify(result)
    except Exception as exc:
        logger.exception("analyse_vulnerability failed")
        return _json_error(str(exc), 500)



@threat_intel_bp.route("/sync", methods=["POST"])
def trigger_sync() -> Response:
    """
    Trigger a manual threat intelligence sync.

    Body (all optional)
    -------------------
    {
      "nvd_days": 7,
      "skip_nvd": false,
      "skip_cisa": false,
      "skip_ghsa": false,
      "background": true
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    nvd_days = int(body.get("nvd_days") or 7)
    skip_nvd = bool(body.get("skip_nvd", False))
    skip_cisa = bool(body.get("skip_cisa", False))
    skip_ghsa = bool(body.get("skip_ghsa", False))
    background = bool(body.get("background", True))

    kwargs = dict(
        nvd_days=nvd_days,
        skip_nvd=skip_nvd,
        skip_cisa=skip_cisa,
        skip_ghsa=skip_ghsa,
    )

    if background:
        thread = threading.Thread(target=run_sync, kwargs=kwargs, daemon=True, name="threat-intel-manual-sync")
        thread.start()
        return jsonify({"status": "sync started in background", "params": kwargs})

    try:
        summary = run_sync(**kwargs)
        return jsonify({"status": "sync complete", "summary": summary})
    except Exception as exc:
        logger.exception("Manual sync failed")
        return _json_error(str(exc), 500)


@threat_intel_bp.route("/store/reset", methods=["DELETE"])
def reset_store() -> Response:
    """
    ⚠️  Danger: Wipe the entire vector store.
    Requires header `X-Confirm-Reset: yes`.
    """
    confirm = request.headers.get("X-Confirm-Reset", "")
    if confirm.lower() != "yes":
        return _json_error(
            "Send header 'X-Confirm-Reset: yes' to confirm store wipe.", 400
        )
    try:
        _get_store().reset()
        return jsonify({"status": "store wiped"})
    except Exception as exc:
        return _json_error(str(exc), 500)
