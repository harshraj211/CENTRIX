"""
scanner/threat_intel/sync_worker.py
--------------------------------------
APScheduler background worker that periodically ingests the latest
vulnerability advisories from NVD, CISA-KEV, and GHSA into ChromaDB.

Architecture
------------
  ┌─────────────────────────────┐
  │  APScheduler (background)   │
  │  ┌───────────────────────┐  │
  │  │ sync_all_feeds()      │  │
  │  │  ├─ NvdFeed           │  │
  │  │  ├─ CisaKevFeed       │  │
  │  │  └─ GhsaFeed          │  │
  │  │       ↓ batches        │  │
  │  │  OllamaClient.embed() │  │
  │  │       ↓ vectors        │  │
  │  │  VectorStore.upsert() │  │
  │  └───────────────────────┘  │
  └─────────────────────────────┘

The worker stores per-feed watermarks (last-sync timestamps) in the
vector store so incremental updates only pull what changed.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import cfg
from .feeds import CisaKevFeed, GhsaFeed, NvdFeed
from .normalizer import AdvisoryRecord
from .ollama_client import OllamaClient
from .vector_store import ThreatIntelVectorStore

logger = logging.getLogger("wraith.threat_intel.sync_worker")

# ─────────────────────────────────────────────────────────────────────────────
# Core async sync logic
# ─────────────────────────────────────────────────────────────────────────────


async def _embed_batch(
    client: OllamaClient,
    records: List[AdvisoryRecord],
) -> List[List[List[float]]]:
    """
    Embed all text chunks for every record in the batch.
    Returns a parallel list of chunk-vector lists.
    """
    # Flatten all chunks across all records
    all_chunks: List[str] = []
    chunk_counts: List[int] = []
    for rec in records:
        chunks = rec.chunk_text()
        all_chunks.extend(chunks)
        chunk_counts.append(len(chunks))

    # Embed in one go (Ollama handles each sequentially internally)
    all_vectors = await client.embed_batch(all_chunks)

    # Re-group by record
    grouped: List[List[List[float]]] = []
    idx = 0
    for count in chunk_counts:
        grouped.append(all_vectors[idx : idx + count])
        idx += count
    return grouped


async def _sync_feed(
    feed_name: str,
    records_gen: Any,  # AsyncIterator[List[AdvisoryRecord]]
    client: OllamaClient,
    store: ThreatIntelVectorStore,
) -> Dict[str, Any]:
    total_records = 0
    total_chunks = 0
    errors = 0

    async for batch in records_gen:
        if not batch:
            continue
        try:
            grouped_embeddings = await _embed_batch(client, batch)
            upserted = store.upsert_records(batch, grouped_embeddings)
            total_records += len(batch)
            total_chunks += upserted
        except Exception as exc:
            logger.error("Batch embed/upsert failed for %s: %s", feed_name, exc)
            errors += 1

    store.set_watermark(feed_name)
    return {
        "feed": feed_name,
        "records": total_records,
        "chunks": total_chunks,
        "errors": errors,
    }


async def sync_all_feeds(
    store: Optional[ThreatIntelVectorStore] = None,
    client: Optional[OllamaClient] = None,
    nvd_days: int = 7,
    skip_nvd: bool = False,
    skip_cisa: bool = False,
    skip_ghsa: bool = False,
) -> Dict[str, Any]:
    """
    Master async sync function – ingest all three feeds.

    Parameters
    ----------
    store    : ThreatIntelVectorStore instance (created if None)
    client   : OllamaClient instance (created if None)
    nvd_days : fetch NVD CVEs modified in the last N days
    skip_*   : disable individual feeds for testing / partial syncs

    Returns a summary dict suitable for logging / API response.
    """
    store = store or ThreatIntelVectorStore()
    client = client or OllamaClient()

    started_at = datetime.now(timezone.utc).isoformat()
    results: List[Dict[str, Any]] = []

    # ── NVD ──────────────────────────────────────────────────────────────────
    if not skip_nvd:
        logger.info("Starting NVD sync (last %d days)…", nvd_days)
        nvd = NvdFeed()
        result = await _sync_feed(
            "NVD",
            nvd.fetch_all_recent(days=nvd_days),
            client,
            store,
        )
        results.append(result)
        logger.info("NVD sync done: %s", result)

    # ── CISA KEV ─────────────────────────────────────────────────────────────
    if not skip_cisa:
        logger.info("Starting CISA-KEV sync…")
        kev = CisaKevFeed()
        result = await _sync_feed(
            "CISA-KEV",
            kev.fetch_all(),
            client,
            store,
        )
        results.append(result)
        logger.info("CISA-KEV sync done: %s", result)

    # ── GHSA ─────────────────────────────────────────────────────────────────
    if not skip_ghsa:
        logger.info("Starting GHSA sync…")
        ghsa = GhsaFeed()
        result = await _sync_feed(
            "GHSA",
            ghsa.fetch_all(),
            client,
            store,
        )
        results.append(result)
        logger.info("GHSA sync done: %s", result)

    summary = {
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "feeds": results,
        "total_records": sum(r.get("records", 0) for r in results),
        "total_chunks": sum(r.get("chunks", 0) for r in results),
        "store_stats": store.stats(),
    }
    logger.info("Sync complete: %d records, %d chunks", summary["total_records"], summary["total_chunks"])
    return summary


def run_sync(**kwargs: Any) -> Dict[str, Any]:
    """Synchronous wrapper – safe to call from APScheduler / Flask."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, sync_all_feeds(**kwargs))
                return future.result()
        return loop.run_until_complete(sync_all_feeds(**kwargs))
    except RuntimeError:
        return asyncio.run(sync_all_feeds(**kwargs))


# ─────────────────────────────────────────────────────────────────────────────
# APScheduler setup
# ─────────────────────────────────────────────────────────────────────────────

_scheduler_instance: Any = None


def get_scheduler() -> Any:
    """
    Return the global APScheduler BackgroundScheduler, creating it if needed.
    """
    global _scheduler_instance
    if _scheduler_instance is not None:
        return _scheduler_instance

    try:
        from apscheduler.schedulers.background import BackgroundScheduler  # type: ignore[import]
        from apscheduler.triggers.interval import IntervalTrigger  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "apscheduler is required. Install with: pip install apscheduler"
        ) from exc

    scheduler = BackgroundScheduler(timezone="UTC")

    scheduler.add_job(
        run_sync,
        trigger=IntervalTrigger(hours=cfg.sync_interval_hours),
        id="threat_intel_sync",
        name="Threat Intelligence Full Sync",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
        kwargs={"nvd_days": 7},
    )

    _scheduler_instance = scheduler
    return scheduler


def start_scheduler() -> None:
    """Start the background scheduler (call once at app startup)."""
    scheduler = get_scheduler()
    if not scheduler.running:
        scheduler.start()
        logger.info(
            "Threat intel scheduler started (interval=%dh).",
            cfg.sync_interval_hours,
        )
        if cfg.sync_on_startup:
            import threading
            thread = threading.Thread(target=run_sync, daemon=True)
            thread.start()
            logger.info("Initial sync triggered in background thread.")


def stop_scheduler() -> None:
    """Gracefully stop the scheduler."""
    global _scheduler_instance
    if _scheduler_instance and _scheduler_instance.running:
        _scheduler_instance.shutdown(wait=False)
        logger.info("Threat intel scheduler stopped.")
