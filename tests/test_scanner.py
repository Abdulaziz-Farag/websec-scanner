import asyncio

import httpx
import pytest

from app import scanner
from app.schemas import Finding, Severity
from app.security import UnsafeTarget


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    def fake_guard(host: str) -> None:
        if host in ("127.0.0.1", "localhost"):
            raise UnsafeTarget("private")

    monkeypatch.setattr(scanner, "assert_public_host", fake_guard)
    monkeypatch.setattr("app.security.assert_public_host", fake_guard)


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_score_and_summary():
    fs = [Finding(check="x", title="a", severity=Severity.high),
          Finding(check="x", title="b", severity=Severity.low)]
    assert scanner.compute_score(fs) == 76
    assert scanner.summarize(fs) == {"info": 0, "low": 1, "medium": 0, "high": 1}


def test_full_scan_finds_issues():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers=[("server", "nginx/1.18.0"), ("set-cookie", "sid=abc")],
                                  text="<html></html>")
        if request.url.path == "/.env":
            return httpx.Response(200, headers={"content-type": "text/plain"}, text="SECRET=1\nTOKEN=2\n")
        return httpx.Response(404)

    async def go():
        async with make_client(handler) as c:
            return await scanner.run_scan("http://example.test", client=c)

    result = asyncio.run(go())
    titles = {f.title for f in result.findings}
    assert "Exposed .env file" in titles
    assert "Server version disclosed" in titles
    assert "No security.txt found" in titles
    assert result.score < 100
    assert result.findings[0].severity == Severity.high  # sorted by severity


def test_redirect_to_private_host_is_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    async def go():
        async with make_client(handler) as c:
            return await scanner.run_scan("http://example.test", client=c)

    with pytest.raises(UnsafeTarget):
        asyncio.run(go())
