"""
scanner/threat_intel/vector_store.py
--------------------------------------
Persistent ChromaDB vector store wrapper.

Responsibilities
----------------
- Create / open a persistent ChromaDB collection on disk.
- Upsert AdvisoryRecord chunks with their Ollama embeddings.
- Semantic similarity search returning ranked AdvisoryRecords.
- Metadata filtering (source, severity, CISA-KEV flag, etc.).
- Store & retrieve sync watermarks (last-fetched timestamps per feed).

ChromaDB uses cosine distance by default; we convert distance → similarity
as  similarity = 1 - distance  so that higher = more relevant.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .config import cfg
from .normalizer import AdvisoryRecord

logger = logging.getLogger("wraith.threat_intel.vector_store")

# Lazy import so the module can be imported even without chromadb installed
_chromadb: Any = None


def _get_chromadb() -> Any:
    global _chromadb
    if _chromadb is None:
        try:
            import chromadb  # type: ignore[import]
            _chromadb = chromadb
        except ImportError as exc:
            raise ImportError(
                "chromadb is required for the threat intel pipeline. "
                "Install it with: pip install chromadb"
            ) from exc
    return _chromadb


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _chunk_id(cve_id: str, chunk_idx: int, source: str) -> str:
    """Deterministic, collision-resistant chunk identifier."""
    raw = f"{source}::{cve_id}::{chunk_idx}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def _flatten_metadata(record: AdvisoryRecord, chunk_idx: int, total_chunks: int) -> Dict[str, Any]:
    """
    ChromaDB metadata values must be str | int | float | bool.
    Lists / nested dicts need to be serialised.
    """
    return {
        "cve_id": record.cve_id,
        "source": record.source,
        "title": record.title[:500],
        "published": record.published,
        "last_modified": record.last_modified,
        "cvss_score": record.cvss_score,
        "severity": record.severity,
        "cwe": record.cwe,
        "cisa_kev": record.cisa_kev,
        "cisa_due_date": record.cisa_due_date,
        "ghsa_id": record.ghsa_id,
        "language": record.language.lower() if record.language else "unknown",
        "affected_packages": json.dumps(record.affected_packages),
        "affected_versions": json.dumps(record.affected_versions),
        "remediation": record.remediation[:800],
        "references": json.dumps(record.references[:8]),
        "chunk_idx": chunk_idx,
        "total_chunks": total_chunks,
    }


def _unflatten_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    for list_key in ("affected_packages", "affected_versions", "references"):
        raw = meta.get(list_key)
        if isinstance(raw, str):
            try:
                meta[list_key] = json.loads(raw)
            except Exception:
                meta[list_key] = []
    meta.setdefault("language", "unknown")
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# Main store class
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelVectorStore:
    """
    Wraps ChromaDB with advisory-specific helper methods.

    Parameters
    ----------
    persist_dir  : path to the ChromaDB storage directory
    collection   : ChromaDB collection name
    """

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        collection: Optional[str] = None,
    ) -> None:
        chromadb = _get_chromadb()
        self.persist_dir = persist_dir or cfg.chroma_persist_dir
        self.collection_name = collection or cfg.chroma_collection

        os.makedirs(self.persist_dir, exist_ok=True)
        self._client = chromadb.PersistentClient(path=self.persist_dir)
        self._col = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        # Separate tiny collection for feed watermarks
        self._watermarks = self._client.get_or_create_collection(
            name=f"{self.collection_name}__watermarks",
        )
        logger.info(
            "ChromaDB opened: %s  (collection=%s, %d docs)",
            self.persist_dir,
            self.collection_name,
            self._col.count(),
        )

    # ── Upsert ───────────────────────────────────────────────────────────────

    def upsert_records(
        self,
        records: List[AdvisoryRecord],
        embeddings: List[List[List[float]]],
    ) -> int:
        """
        Upsert a batch of AdvisoryRecords.

        Parameters
        ----------
        records    : list of AdvisoryRecord
        embeddings : parallel list; each element is a list of chunk-vectors
                     (one per chunk of the corresponding record)

        Returns
        -------
        Number of chunks upserted.
        """
        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []
        embeds: List[List[float]] = []

        for record, chunk_vectors in zip(records, embeddings):
            chunks = record.chunk_text()
            if len(chunks) != len(chunk_vectors):
                # Fall back: use first vector for all chunks (shouldn't happen)
                chunk_vectors = [chunk_vectors[0]] * len(chunks) if chunk_vectors else []
            for idx, (chunk, vec) in enumerate(zip(chunks, chunk_vectors)):
                if not vec:
                    continue
                ids.append(_chunk_id(record.cve_id, idx, record.source))
                docs.append(chunk)
                metas.append(_flatten_metadata(record, idx, len(chunks)))
                embeds.append(vec)

        if not ids:
            return 0

        # ChromaDB upsert is idempotent on ID collision
        self._col.upsert(
            ids=ids,
            documents=docs,
            metadatas=metas,
            embeddings=embeds,
        )
        logger.debug("Upserted %d chunks for %d records", len(ids), len(records))
        return len(ids)

    # ── Query ────────────────────────────────────────────────────────────────

    def query(
        self,
        query_embedding: List[float],
        top_k: int = 8,
        min_similarity: float = 0.25,
        where: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[float, Dict[str, Any]]]:
        """
        Semantic similarity search.

        Returns
        -------
        List of (similarity_score, metadata_dict) sorted by score desc.
        """
        if not query_embedding:
            return []
        try:
            results = self._col.query(
                query_embeddings=[query_embedding],
                n_results=min(top_k * 2, max(1, self._col.count())),
                where=where,
                include=["metadatas", "distances", "documents"],
            )
        except Exception as exc:
            logger.error("ChromaDB query failed: %s", exc)
            return []

        output: List[Tuple[float, Dict[str, Any]]] = []
        distances = (results.get("distances") or [[]])[0]
        metadatas = (results.get("metadatas") or [[]])[0]
        documents = (results.get("documents") or [[]])[0]

        seen_cves: set = set()
        for dist, meta, doc in zip(distances, metadatas, documents):
            similarity = 1.0 - float(dist)
            if similarity < min_similarity:
                continue
            meta = _unflatten_metadata(dict(meta))
            cve_id = meta.get("cve_id", "")
            if cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)
            meta["_chunk_text"] = doc
            meta["_similarity"] = round(similarity, 4)
            output.append((similarity, meta))

        output.sort(key=lambda x: x[0], reverse=True)
        return output[:top_k]

    # ── Watermarks ───────────────────────────────────────────────────────────

    def get_watermark(self, feed: str) -> Optional[str]:
        """Return ISO timestamp of last successful sync for a feed, or None."""
        try:
            result = self._watermarks.get(ids=[f"wm_{feed}"])
            docs = result.get("documents") or []
            return docs[0] if docs else None
        except Exception:
            return None

    def set_watermark(self, feed: str, timestamp: Optional[str] = None) -> None:
        """Persist the sync watermark for a feed."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        try:
            self._watermarks.upsert(
                ids=[f"wm_{feed}"],
                documents=[ts],
                embeddings=[[0.0]],   # dummy embedding (watermarks aren't queried)
            )
        except Exception as exc:
            logger.warning("Failed to save watermark for %s: %s", feed, exc)

    # ── Introspection ────────────────────────────────────────────────────────

    def count(self) -> int:
        return self._col.count()

    def stats(self) -> Dict[str, Any]:
        feeds = ["NVD", "GHSA", "CISA-KEV"]
        watermarks = {f: self.get_watermark(f) for f in feeds}
        return {
            "total_chunks": self.count(),
            "collection": self.collection_name,
            "persist_dir": self.persist_dir,
            "watermarks": watermarks,
        }

    def delete_by_cve(self, cve_id: str) -> int:
        """Remove all chunks for a given CVE ID."""
        try:
            result = self._col.get(where={"cve_id": cve_id})
            ids = result.get("ids") or []
            if ids:
                self._col.delete(ids=ids)
            return len(ids)
        except Exception as exc:
            logger.warning("delete_by_cve(%s) failed: %s", cve_id, exc)
            return 0

    def reset(self) -> None:
        """Danger: wipe the entire collection."""
        self._client.delete_collection(self.collection_name)
        self._col = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.warning("Collection %s wiped.", self.collection_name)
