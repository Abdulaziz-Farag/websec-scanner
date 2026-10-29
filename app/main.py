from __future__ import annotations

import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from app import __version__, scanner
from app.report import render_html
from app.schemas import ScanRequest, ScanResult
from app.security import UnsafeTarget

app = FastAPI(
    title="WebSec Scanner",
    version=__version__,
    description="Passive web security scanner. Scan only systems you are authorized to test.",
)

_STORE: dict[str, ScanResult] = {}
_MAX_STORED = 200


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("WEBSEC_API_KEY")
    if not expected:
        return  # auth disabled (local development)
    if not x_api_key or not secrets.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def _get_or_404(scan_id: str) -> ScanResult:
    result = _STORE.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/scans", response_model=ScanResult, status_code=201, dependencies=[Depends(require_api_key)])
async def create_scan(req: ScanRequest) -> ScanResult:
    try:
        result = await scanner.run_scan(req.target)
    except UnsafeTarget as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _STORE[result.id] = result
    while len(_STORE) > _MAX_STORED:
        _STORE.pop(next(iter(_STORE)))
    return result


@app.get("/scans/{scan_id}", response_model=ScanResult, dependencies=[Depends(require_api_key)])
def get_scan(scan_id: str) -> ScanResult:
    return _get_or_404(scan_id)


@app.get("/scans/{scan_id}/report", response_class=HTMLResponse, dependencies=[Depends(require_api_key)])
def get_report(scan_id: str) -> str:
    return render_html(_get_or_404(scan_id))
