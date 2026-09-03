"""
scanner/threat_intel/feeds.py
-------------------------------
Async ingestion of public vulnerability feeds:
  - NVD CVE API 2.0  (with NVD_API_KEY support, 5 req / 30 s rate limit)
  - GitHub Security Advisory Database (GraphQL, paginated)
  - CISA Known Exploited Vulnerabilities catalog (single JSON bulk download)

All feed fetchers implement:
  - Exponential backoff on 429 / 503 / transient errors
  - startIndex / since-date continuation via watermarks
  - Yields batches of AdvisoryRecord for streaming ingestion
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncIterator, Dict, List, Optional, Any

import httpx

from .config import cfg
from .normalizer import (
    AdvisoryRecord,
    parse_nvd_item,
    parse_cisa_kev_item,
    parse_ghsa_node,
)

logger = logging.getLogger("wraith.threat_intel.feeds")

BATCH_SIZE = 50          # advisory records per yield
NVD_PAGE_SIZE = 2000     # max NVD allows per request


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _sleep_backoff(attempt: int, base: float = 2.0, cap: float = 60.0) -> None:
    import random
    delay = min(base ** attempt, cap) * (0.5 + random.random() * 0.5)
    logger.debug("Backoff sleep %.1fs (attempt %d)", delay, attempt)
    await asyncio.sleep(delay)


async def _get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    max_retries: int = 4,
) -> Optional[Dict[str, Any]]:
    """GET with exponential backoff; returns None on permanent failure."""
    for attempt in range(max_retries):
        try:
            resp = await client.get(url, params=params, headers=headers)
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", 10))
                logger.warning("Rate-limited by %s; sleeping %.0fs", url, retry_after)
                await asyncio.sleep(retry_after)
                continue
            if resp.status_code in {500, 502, 503, 504}:
                await _sleep_backoff(attempt)
                continue
            resp.raise_for_status()
            return resp.json()
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
            if attempt < max_retries - 1:
                logger.warning("Transient error fetching %s: %s", url, exc)
                await _sleep_backoff(attempt)
            else:
                logger.error("Permanent failure fetching %s after %d retries: %s", url, max_retries, exc)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NVD CVE API 2.0
# ─────────────────────────────────────────────────────────────────────────────

class NvdFeed:
    """
    Fetches CVEs from the NVD CVE API 2.0.

    Without an API key: 5 req / 30 s window (we enforce this internally).
    With an API key  : 50 req / 30 s window.
    """

    API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self) -> None:
        self.api_key = cfg.nvd_api_key
        self._request_times: List[float] = []
        self._limit = 50 if self.api_key else cfg.nvd_rate_limit_per_30s

    def _headers(self) -> Dict[str, str]:
        h = {"User-Agent": "WraithScanner/4 (threat-intel-pipeline)"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    async def _enforce_rate_limit(self) -> None:
        """Block until we are within the 30-second sliding window."""
        now = time.monotonic()
        self._request_times = [t for t in self._request_times if now - t < 30]
        if len(self._request_times) >= self._limit:
            sleep_for = 30 - (now - self._request_times[0]) + 0.5
            if sleep_for > 0:
                logger.debug("NVD rate-limit: sleeping %.1fs", sleep_for)
                await asyncio.sleep(sleep_for)
        self._request_times.append(time.monotonic())

    async def fetch_since(
        self,
        last_modified_start: Optional[str] = None,
        last_modified_end: Optional[str] = None,
    ) -> AsyncIterator[List[AdvisoryRecord]]:
        """
        Async-generator: yields batches of AdvisoryRecords.

        Parameters
        ----------
        last_modified_start : ISO8601 – only fetch CVEs modified after this date
        last_modified_end   : ISO8601 – (optional) upper bound
        """
        params: Dict[str, Any] = {"resultsPerPage": NVD_PAGE_SIZE, "startIndex": 0}
        if last_modified_start:
            params["lastModStartDate"] = last_modified_start
            if last_modified_end:
                params["lastModEndDate"] = last_modified_end

        total_fetched = 0
        timeout = httpx.Timeout(cfg.feed_request_timeout)

        async with httpx.AsyncClient(timeout=timeout) as client:
            while True:
                await self._enforce_rate_limit()
                data = await _get_json(client, self.API, params=params, headers=self._headers())
                if data is None:
                    break

                vulnerabilities = data.get("vulnerabilities") or []
                total_results = data.get("totalResults", 0)
                results_per_page = data.get("resultsPerPage", NVD_PAGE_SIZE)

                batch: List[AdvisoryRecord] = []
                for vuln in vulnerabilities:
                    try:
                        record = parse_nvd_item(vuln)
                        if record.cve_id:
                            batch.append(record)
                    except Exception as exc:
                        logger.debug("NVD parse error: %s", exc)

                if batch:
                    yield batch

                total_fetched += len(vulnerabilities)
                if total_fetched >= total_results or not vulnerabilities:
                    break

                params["startIndex"] = total_fetched

    async def fetch_all_recent(self, days: int = 7) -> AsyncIterator[List[AdvisoryRecord]]:
        """Fetch CVEs modified in the last `days` days."""
        from datetime import datetime, timedelta, timezone
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        async for batch in self.fetch_since(
            last_modified_start=start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            last_modified_end=end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        ):
            yield batch


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV (single bulk JSON download)
# ─────────────────────────────────────────────────────────────────────────────

class CisaKevFeed:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch_all(self) -> AsyncIterator[List[AdvisoryRecord]]:
        timeout = httpx.Timeout(cfg.feed_request_timeout * 2)
        async with httpx.AsyncClient(timeout=timeout) as client:
            data = await _get_json(client, self.URL)
        if data is None:
            logger.error("CISA KEV fetch returned None")
            return

        records: List[AdvisoryRecord] = []
        for item in data.get("vulnerabilities") or []:
            try:
                record = parse_cisa_kev_item(item)
                if record.cve_id:
                    records.append(record)
            except Exception as exc:
                logger.debug("CISA KEV parse error: %s", exc)

            if len(records) >= BATCH_SIZE:
                yield records
                records = []

        if records:
            yield records


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Security Advisory Database (GraphQL)
# ─────────────────────────────────────────────────────────────────────────────

GHSA_GRAPHQL_QUERY = """
query($after: String, $first: Int!) {
  securityAdvisories(first: $first, after: $after, orderBy: {field: UPDATED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss { score vectorString }
      cwes(first: 5) { nodes { cweId } }
      identifiers { type value }
      references { url }
      vulnerabilities(first: 20) {
        nodes {
          package { name ecosystem }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
  }
}
"""


class GhsaFeed:
    """
    Fetches advisories from the GitHub Security Advisory Database via GraphQL.
    Requires a GitHub personal access token with no specific scopes (public data).
    """

    URL = "https://api.github.com/graphql"

    def __init__(self) -> None:
        self.token = cfg.github_token

    async def fetch_all(
        self, max_pages: int = 20, page_size: int = 50
    ) -> AsyncIterator[List[AdvisoryRecord]]:
        if not self.token:
            logger.warning("GITHUB_TOKEN not set; skipping GHSA feed.")
            return

        headers = {
            "Authorization": f"bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": "WraithScanner/4",
        }
        cursor: Optional[str] = None
        page = 0

        timeout = httpx.Timeout(cfg.feed_request_timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            while page < max_pages:
                variables: Dict[str, Any] = {"first": page_size}
                if cursor:
                    variables["after"] = cursor

                for attempt in range(cfg.feed_max_retries):
                    try:
                        resp = await client.post(
                            self.URL,
                            headers=headers,
                            json={"query": GHSA_GRAPHQL_QUERY, "variables": variables},
                        )
                        if resp.status_code == 429:
                            retry_after = float(resp.headers.get("Retry-After", 60))
                            logger.warning("GHSA rate-limited; sleeping %.0fs", retry_after)
                            await asyncio.sleep(retry_after)
                            continue
                        resp.raise_for_status()
                        payload = resp.json()
                        break
                    except Exception as exc:
                        if attempt < cfg.feed_max_retries - 1:
                            await _sleep_backoff(attempt)
                        else:
                            logger.error("GHSA fetch error: %s", exc)
                            return
                else:
                    return

                errors = payload.get("errors")
                if errors:
                    logger.error("GHSA GraphQL errors: %s", errors)
                    return

                sa_data = (payload.get("data") or {}).get("securityAdvisories") or {}
                nodes = sa_data.get("nodes") or []
                page_info = sa_data.get("pageInfo") or {}

                records: List[AdvisoryRecord] = []
                for node in nodes:
                    try:
                        record = parse_ghsa_node(node)
                        if record:
                            records.append(record)
                    except Exception as exc:
                        logger.debug("GHSA parse error: %s", exc)

                if records:
                    yield records

                if not page_info.get("hasNextPage"):
                    break

                cursor = page_info.get("endCursor")
                page += 1
                # Be polite: GitHub GraphQL has a secondary rate limit
                await asyncio.sleep(1.0)
