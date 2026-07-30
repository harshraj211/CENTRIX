"""
Stage 1 — Target Validation
Checks: DNS resolution, TCP reachability, SSL/TLS cert, robots.txt
All checks run concurrently via asyncio.gather for minimum latency.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urlparse
from typing import Callable, Awaitable

import aiohttp


async def run(
    target: str,
    log: Callable[[str], Awaitable[None]],
    timeout: int = 10,
) -> dict:
    """
    Returns:
        {
            "resolved_ip": str | None,
            "latency_ms": float | None,
            "ssl_valid": bool,
            "ssl_version": str | None,
            "robots_blocked_paths": list[str],
        }
    """
    parsed = urlparse(target)
    hostname = parsed.hostname or target.split("//")[-1].split("/")[0]

    await log(f"[INFO] Starting target validation for {hostname}...")

    ip, latency, ssl_info, robots_paths = await asyncio.gather(
        _resolve_dns(hostname, log),
        _tcp_ping(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), log),
        _check_ssl(hostname, parsed.scheme, log),
        _fetch_robots(target, log, timeout),
        return_exceptions=True,
    )

    # Unpack (handle exceptions gracefully)
    resolved_ip = ip if isinstance(ip, str) else None
    latency_ms = latency if isinstance(latency, float) else None
    ssl_valid = ssl_info.get("valid", False) if isinstance(ssl_info, dict) else False
    ssl_version = ssl_info.get("version") if isinstance(ssl_info, dict) else None
    blocked = robots_paths if isinstance(robots_paths, list) else []

    await log(f"[SUCCESS] Validation complete — IP: {resolved_ip or 'N/A'}, "
              f"Latency: {f'{latency_ms:.0f}ms' if latency_ms else 'N/A'}, "
              f"SSL: {'OK' if ssl_valid else 'WARN'}")

    return {
        "resolved_ip": resolved_ip,
        "latency_ms": latency_ms,
        "ssl_valid": ssl_valid,
        "ssl_version": ssl_version,
        "robots_blocked_paths": blocked,
    }


async def _resolve_dns(hostname: str, log) -> str:
    await log(f"[INFO] Resolving DNS for {hostname}...")
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None)
        ip = infos[0][4][0]
        await log(f"[SUCCESS] DNS resolved: {hostname} → {ip}")
        return ip
    except Exception as e:
        await log(f"[WARN] DNS resolution failed: {e}")
        return ""


async def _tcp_ping(hostname: str, port: int, log) -> float:
    import time
    await log(f"[INFO] TCP ping {hostname}:{port}...")
    try:
        t0 = time.perf_counter()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=8
        )
        elapsed = (time.perf_counter() - t0) * 1000
        writer.close()
        await writer.wait_closed()
        await log(f"[SUCCESS] TCP latency: {elapsed:.0f}ms")
        return elapsed
    except Exception as e:
        await log(f"[WARN] TCP ping failed: {e}")
        return 0.0


async def _check_ssl(hostname: str, scheme: str, log) -> dict:
    if scheme != "https":
        await log("[INFO] Skipping SSL check (non-HTTPS target).")
        return {"valid": False, "version": None}
    try:
        await log(f"[INFO] Checking SSL/TLS for {hostname}...")
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()
        conn = await loop.run_in_executor(
            None, lambda: ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=8),
                server_hostname=hostname
            )
        )
        version = conn.version()
        conn.close()
        if version in ("TLSv1", "TLSv1.1"):
            await log(f"[WARN] Outdated TLS version detected: {version} (CVE-2015-2808 risk)")
        else:
            await log(f"[SUCCESS] SSL/TLS OK — {version}")
        return {"valid": True, "version": version}
    except Exception as e:
        await log(f"[WARN] SSL check error: {e}")
        return {"valid": False, "version": None}


async def _fetch_robots(target: str, log, timeout: int) -> list[str]:
    robots_url = target.rstrip("/") + "/robots.txt"
    await log(f"[INFO] Fetching robots.txt from {robots_url}...")
    blocked: list[str] = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                robots_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                blocked.append(path)
                    await log(f"[INFO] robots.txt: {len(blocked)} disallow rules found")
                else:
                    await log(f"[INFO] No robots.txt found (HTTP {resp.status})")
    except Exception as e:
        await log(f"[INFO] robots.txt not accessible: {e}")
    return blocked
