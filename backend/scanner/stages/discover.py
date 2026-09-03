"""
Stage 2 — Discovery & Enumeration
- Async TCP port scan (common ports)
- Common directory/path brute-force (aiohttp + semaphore)
- vHost fuzzing (limited, passive)
Results in a list of discovered endpoints/paths.
"""
from __future__ import annotations

import asyncio
from typing import Callable, Awaitable
from urllib.parse import urlparse

import aiohttp

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000]

COMMON_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/admin", "/login",
    "/dashboard", "/health", "/status", "/metrics", "/debug",
    "/swagger", "/swagger.json", "/openapi.json", "/docs",
    "/graphql", "/users", "/search", "/export", "/upload",
    "/.env", "/.git/config", "/config", "/wp-admin",
    "/backup", "/phpinfo.php", "/server-info",
]


async def run(
    target: str,
    log: Callable[[str], Awaitable[None]],
    timeout: int = 10,
    concurrency: int = 20,
) -> dict:
    """Returns discovered ports and reachable paths."""
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    base = f"{parsed.scheme}://{parsed.netloc}"

    await log("[INFO] Starting Discovery & Enumeration phase...")

    # Port scan + path brute-force in parallel
    open_ports, reachable_paths = await asyncio.gather(
        _port_scan(hostname, log),
        _path_bruteforce(base, log, timeout, concurrency),
    )

    await log(
        f"[SUCCESS] Discovery complete — {len(open_ports)} open ports, "
        f"{len(reachable_paths)} paths found"
    )

    return {"open_ports": open_ports, "paths": reachable_paths}


async def _port_scan(hostname: str, log) -> list[int]:
    """Concurrent TCP connect scan on common ports."""
    await log(f"[INFO] TCP port scanning {hostname} ({len(COMMON_PORTS)} ports)...")
    sem = asyncio.Semaphore(len(COMMON_PORTS))  # all at once — they're fast

    async def try_port(port: int) -> int | None:
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port), timeout=3
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception:
                return None

    results = await asyncio.gather(*[try_port(p) for p in COMMON_PORTS])
    open_ports = [p for p in results if p is not None]

    for port in open_ports:
        await log(f"[INFO] Open port: {hostname}:{port}")

    return open_ports


async def _path_bruteforce(
    base: str,
    log,
    timeout: int,
    concurrency: int,
) -> list[str]:
    """Async directory enumeration — respects concurrency limit."""
    await log(f"[INFO] Path enumeration on {base} ({len(COMMON_PATHS)} checks)...")
    sem = asyncio.Semaphore(concurrency)
    found: list[str] = []

    async def check_path(path: str) -> str | None:
        async with sem:
            url = base.rstrip("/") + path
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        if resp.status not in (404, 403, 410):
                            return path
            except Exception:
                pass
            return None

    results = await asyncio.gather(*[check_path(p) for p in COMMON_PATHS])
    found = [p for p in results if p is not None]

    await log(f"[INFO] Paths discovered: {len(found)}")
    for p in found[:5]:   # log first 5 to avoid spam
        await log(f"[INFO] ↳ Reachable: {p}")

    return found
