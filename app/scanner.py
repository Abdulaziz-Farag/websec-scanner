"""Scan orchestration: fetch the target, run passive checks, score the result."""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urljoin, urlparse

import httpx

from app.checks import exposed, headers, tls
from app.schemas import Finding, ScanResult, Severity
from app.security import UnsafeTarget, assert_public_host, validate_target

USER_AGENT = "WebSecScanner/0.1 (passive checks; authorized testing only)"
MAX_REDIRECTS = 3
SNIPPET_BYTES = 2048
CONCURRENCY = 4
WEIGHTS = {Severity.high: 20, Severity.medium: 10, Severity.low: 4, Severity.info: 0}
_ORDER = {Severity.high: 0, Severity.medium: 1, Severity.low: 2, Severity.info: 3}


async def safe_get(client: httpx.AsyncClient, url: str):
    """GET that follows redirects manually: every hop is re-checked by the SSRF guard
    and only the first ``SNIPPET_BYTES`` of the body are read."""
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise UnsafeTarget("Redirect to a non-http(s) URL")
        await asyncio.to_thread(assert_public_host, parsed.hostname or "")
        async with client.stream("GET", url) as resp:
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) >= SNIPPET_BYTES:
                    break
            if resp.is_redirect and "location" in resp.headers:
                url = urljoin(url, resp.headers["location"])
                continue
            text = body[:SNIPPET_BYTES].decode("utf-8", "replace")
            return resp.status_code, resp.headers, text, url
    raise UnsafeTarget("Too many redirects")


def compute_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(WEIGHTS[f.severity] for f in findings))


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


async def run_scan(raw_target: str, client: httpx.AsyncClient | None = None) -> ScanResult:
    started = time.perf_counter()
    base = await validate_target(raw_target)
    parsed = urlparse(base)
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(8.0), follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )
    findings: list[Finding] = []
    try:
        try:
            _, hdrs, _, final_url = await safe_get(client, base + "/")
        except httpx.HTTPError as exc:
            findings.append(Finding(check="availability", title="Target unreachable",
                                    severity=Severity.info, detail=type(exc).__name__))
            hdrs, final_url = None, base
        if hdrs is not None:
            is_https = final_url.startswith("https://")
            findings += headers.analyze_headers(hdrs, is_https)
            findings += headers.analyze_cookies(hdrs.get_list("set-cookie"), is_https)

            sem = asyncio.Semaphore(CONCURRENCY)

            async def run_probe(probe: exposed.Probe) -> Finding | None:
                async with sem:
                    try:
                        status, h, body, _ = await safe_get(client, base + probe.path)
                    except (httpx.HTTPError, UnsafeTarget):
                        return None
                if probe.validator(status, h.get("content-type", ""), body):
                    return exposed.probe_to_finding(probe, base + probe.path)
                return None

            async def run_security_txt() -> Finding | None:
                try:
                    status, _, body, _ = await safe_get(client, base + "/.well-known/security.txt")
                except (httpx.HTTPError, UnsafeTarget):
                    status, body = 0, ""
                return exposed.check_security_txt(status, body)

            results = await asyncio.gather(*(run_probe(p) for p in exposed.PROBES), run_security_txt())
            findings += [r for r in results if r is not None]

        if parsed.scheme == "https":
            findings += await asyncio.to_thread(tls.inspect_tls, parsed.hostname or "", parsed.port or 443)
    finally:
        if owns_client:
            await client.aclose()

    findings.sort(key=lambda f: _ORDER[f.severity])
    return ScanResult(
        target=base, findings=findings, score=compute_score(findings),
        summary=summarize(findings), duration_ms=int((time.perf_counter() - started) * 1000),
    )
