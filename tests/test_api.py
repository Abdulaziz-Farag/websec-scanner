import pytest
from fastapi.testclient import TestClient

from app import main, scanner
from app.schemas import Finding, ScanResult, Severity
from app.security import UnsafeTarget

client = TestClient(main.app)


def fake_result() -> ScanResult:
    return ScanResult(
        target="https://example.com",
        findings=[Finding(check="headers", title="<img src=x onerror=alert(1)>",
                          severity=Severity.low, detail="<script>alert(1)</script>")],
    )


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    main._STORE.clear()
    monkeypatch.delenv("WEBSEC_API_KEY", raising=False)

    async def fake_scan(target: str) -> ScanResult:
        return fake_result()

    monkeypatch.setattr(scanner, "run_scan", fake_scan)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_create_and_fetch_scan():
    r = client.post("/scans", json={"target": "example.com"})
    assert r.status_code == 201
    assert client.get(f"/scans/{r.json()['id']}").status_code == 200
    assert client.get("/scans/unknown").status_code == 404


def test_unsafe_target_returns_400(monkeypatch):
    async def boom(target: str):
        raise UnsafeTarget("Refusing to scan non-public address: 127.0.0.1")

    monkeypatch.setattr(scanner, "run_scan", boom)
    assert client.post("/scans", json={"target": "localhost"}).status_code == 400


def test_api_key_enforced(monkeypatch):
    monkeypatch.setenv("WEBSEC_API_KEY", "s3cret")
    assert client.post("/scans", json={"target": "example.com"}).status_code == 401
    bad = client.post("/scans", json={"target": "example.com"}, headers={"X-API-Key": "nope"})
    assert bad.status_code == 401
    ok = client.post("/scans", json={"target": "example.com"}, headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 201


def test_report_escapes_attacker_controlled_values():
    scan_id = client.post("/scans", json={"target": "example.com"}).json()["id"]
    html = client.get(f"/scans/{scan_id}/report").text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
