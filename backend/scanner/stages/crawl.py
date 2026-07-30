"""
Stage 3 — Crawling & Sitemap
- Recursive async HTML crawler using aiohttp
- Deduplication via set() — O(1) membership test
- Extracts links, forms, input parameters
"""
from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Callable, Awaitable
from urllib.parse import urljoin, urlparse

import aiohttp


class _LinkParser(HTMLParser):
    """Lightweight parser — no external deps, pure stdlib."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self._current_inputs: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        attr = dict(attrs)
        if tag == "a" and "href" in attr:
            self.links.append(urljoin(self.base, attr["href"]))
        elif tag == "form":
            self._current_form = {"action": urljoin(self.base, attr.get("action", "")),
                                   "method": attr.get("method", "GET").upper()}
            self._current_inputs = []
        elif tag == "input" and self._current_form is not None:
            name = attr.get("name", "")
            if name:
                self._current_inputs.append(name)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            self._current_form["inputs"] = self._current_inputs
            self.forms.append(self._current_form)
            self._current_form = None


def _same_origin(base: str, url: str) -> bool:
    bp = urlparse(base)
    up = urlparse(url)
    return bp.netloc == up.netloc


async def run(
    target: str,
    discovered_paths: list[str],
    log: Callable[[str], Awaitable[None]],
    depth: int = 3,
    timeout: int = 20,
    concurrency: int = 20,
) -> dict:
    """Returns all unique URLs found + forms with their inputs."""
    await log(f"[INFO] Starting crawl from {target} (depth={depth}, concurrency={concurrency})...")

    visited: set[str] = set()
    forms: list[dict] = []
    sem = asyncio.Semaphore(concurrency)

    # Seed with discovered paths
    seeds = [target] + [target.rstrip("/") + p for p in discovered_paths[:20]]

    async def crawl(url: str, current_depth: int) -> None:
        # O(1) dedup
        clean = url.split("#")[0].split("?")[0]
        if clean in visited or current_depth > depth or not _same_origin(target, url):
            return
        visited.add(clean)

        async with sem:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=True,
                        ssl=False,
                        headers={"User-Agent": "VulnGuard/4.0 SecurityScanner"},
                    ) as resp:
                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" not in content_type and "application/json" not in content_type:
                            return
                        body = await resp.text(errors="replace")
            except Exception as e:
                await log(f"[WARN] Crawl error {url}: {e}")
                return

        parser = _LinkParser(url)
        try:
            parser.feed(body)
        except Exception:
            pass

        forms.extend(parser.forms)

        # Recurse concurrently on new links
        children = [
            link for link in parser.links
            if link.split("#")[0].split("?")[0] not in visited
            and link.startswith("http")
        ]
        if children:
            await asyncio.gather(*[crawl(l, current_depth + 1) for l in children[:30]])

    # Start crawling all seeds concurrently
    await asyncio.gather(*[crawl(s, 0) for s in seeds])

    # Extract query parameters from discovered URLs
    params: set[str] = set()
    for url in visited:
        if "?" in url:
            qs = url.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" in part:
                    params.add(part.split("=")[0])

    for form in forms:
        params.update(form.get("inputs", []))

    await log(f"[SUCCESS] Crawl finished — {len(visited)} unique URLs, "
              f"{len(forms)} forms, {len(params)} parameters found")

    return {
        "urls": list(visited),
        "forms": forms,
        "parameters": list(params),
    }
