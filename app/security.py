"""Target validation. The scanner must never be usable as an SSRF proxy."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTarget(ValueError):
    """Raised when a target is malformed or points at a non-public address."""


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeTarget("Target must be a valid http(s) URL or hostname")
    if parsed.username or parsed.password:
        raise UnsafeTarget("Credentials in the URL are not allowed")
    return f"{parsed.scheme}://{parsed.netloc.lower()}"


def assert_public_host(host: str) -> None:
    """Resolve ``host`` and reject it unless every address is globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"Cannot resolve host: {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise UnsafeTarget(f"Refusing to scan non-public address: {ip}")


async def validate_target(raw: str) -> str:
    url = normalize_target(raw)
    host = urlparse(url).hostname or ""
    await asyncio.to_thread(assert_public_host, host)
    return url
