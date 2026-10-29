from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class Finding(BaseModel):
    check: str
    title: str
    severity: Severity
    detail: str = ""
    recommendation: str | None = None


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=255, examples=["example.com"])


class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    target: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = 0
    score: int = 100
    summary: dict[str, int] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
