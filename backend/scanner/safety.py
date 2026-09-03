"""Target and scope safety controls shared by scanner stages."""
from __future__ import annotations

import ipaddress
import socket
from fnmatch import fnmatch
from urllib.parse import urlparse


class TargetSafetyError(ValueError):
    """Raised when a target could reach a local or non-public network."""


def normalise_target(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetSafetyError("Target must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise TargetSafetyError("Targets containing credentials are not allowed")
    return parsed.geturl()


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return ip.is_global


async def ensure_public_target(url: str) -> None:
    """Resolve a hostname and reject loopback, RFC1918, link-local and reserved IPs."""
    parsed = urlparse(normalise_target(url))
    host = parsed.hostname or ""
    try:
        records = await __import__("asyncio").get_running_loop().getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetSafetyError(f"Could not resolve target hostname: {host}") from exc
    addresses = {record[4][0] for record in records}
    if not addresses or any(not _is_public_ip(address) for address in addresses):
        raise TargetSafetyError("Targets resolving to private, local, or reserved addresses are not allowed")


def url_in_scope(url: str, target: str, patterns: list[str]) -> bool:
    """Allow the target origin by default; explicit scope patterns can narrow it."""
    candidate = urlparse(url)
    base = urlparse(target)
    if candidate.scheme not in {"http", "https"} or candidate.netloc != base.netloc:
        return False
    if not patterns:
        return True
    clean = url.split("#", 1)[0]
    return any(fnmatch(clean, pattern.strip()) for pattern in patterns if pattern.strip())
