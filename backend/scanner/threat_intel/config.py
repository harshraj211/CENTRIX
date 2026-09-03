"""
scanner/threat_intel/config.py
------------------------------
Central configuration for the Wraith Threat Intelligence RAG pipeline.
All values are read from environment variables so nothing sensitive is
hard-coded.  Copy .env.example → .env and populate the relevant keys.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(value: str, default: bool = False) -> bool:
    return str(value).lower() in {"1", "true", "yes"} if value else default


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass
class ThreatIntelConfig:
    # ── Ollama ─────────────────────────────────────────────────────────────
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    )
    ollama_chat_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_CHAT_MODEL", "qwen2.5-coder:7b")
    )
    ollama_fast_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_FAST_MODEL", "qwen2.5-coder:1.5b")
    )
    ollama_embed_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
    )
    ollama_timeout: int = field(
        default_factory=lambda: _int(os.getenv("OLLAMA_TIMEOUT", ""), 120)
    )
    ollama_max_retries: int = field(
        default_factory=lambda: _int(os.getenv("OLLAMA_MAX_RETRIES", ""), 3)
    )

    # ── ChromaDB vector store ───────────────────────────────────────────────
    chroma_persist_dir: str = field(
        default_factory=lambda: os.getenv(
            "CHROMA_PERSIST_DIR",
            str(Path.home() / ".wraith" / "chroma_db"),
        )
    )
    chroma_collection: str = field(
        default_factory=lambda: os.getenv("CHROMA_COLLECTION", "wraith_threat_intel")
    )

    # ── Feed / API keys ─────────────────────────────────────────────────────
    nvd_api_key: str = field(
        default_factory=lambda: os.getenv("NVD_API_KEY", "")
    )
    github_token: str = field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN", "")
    )

    # ── Rate limiting & backoff ─────────────────────────────────────────────
    feed_request_timeout: int = field(
        default_factory=lambda: _int(os.getenv("FEED_REQUEST_TIMEOUT", ""), 30)
    )
    feed_max_retries: int = field(
        default_factory=lambda: _int(os.getenv("FEED_MAX_RETRIES", ""), 4)
    )
    feed_backoff_base: float = field(
        default_factory=lambda: _float(os.getenv("FEED_BACKOFF_BASE", ""), 2.0)
    )
    nvd_rate_limit_per_30s: int = field(
        default_factory=lambda: _int(os.getenv("NVD_RATE_LIMIT_PER_30S", ""), 5)
    )

    # ── Sync schedule ───────────────────────────────────────────────────────
    sync_interval_hours: int = field(
        default_factory=lambda: _int(os.getenv("THREAT_INTEL_SYNC_HOURS", ""), 6)
    )
    sync_on_startup: bool = field(
        default_factory=lambda: _bool(os.getenv("THREAT_INTEL_SYNC_ON_STARTUP", "false"))
    )

    # ── RAG retrieval ───────────────────────────────────────────────────────
    rag_top_k: int = field(
        default_factory=lambda: _int(os.getenv("RAG_TOP_K", ""), 8)
    )
    rag_min_relevance: float = field(
        default_factory=lambda: _float(os.getenv("RAG_MIN_RELEVANCE", ""), 0.30)
    )

    # ── Misc ────────────────────────────────────────────────────────────────
    debug: bool = field(
        default_factory=lambda: _bool(os.getenv("THREAT_INTEL_DEBUG", "false"))
    )


# Singleton – import and use `cfg` everywhere inside the sub-package.
cfg = ThreatIntelConfig()
