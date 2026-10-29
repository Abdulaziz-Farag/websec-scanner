"""Passive checks for commonly exposed files. Validators cut false positives
(many sites answer 200 with a generic HTML page for any path)."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from app.schemas import Finding, Severity

Validator = Callable[[int, str, str], bool]  # (status, content_type, body_snippet)


def _is_html(ctype: str) -> bool:
    return "html" in ctype.lower()


def _git_head(status: int, ctype: str, body: str) -> bool:
    return status == 200 and body.lstrip().startswith("ref:")


def _dotenv(status: int, ctype: str, body: str) -> bool:
    if status != 200 or _is_html(ctype):
        return False
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
    return bool(lines) and sum("=" in ln for ln in lines) / len(lines) > 0.6


def _phpinfo(status: int, ctype: str, body: str) -> bool:
    return status == 200 and "phpinfo()" in body


def _server_status(status: int, ctype: str, body: str) -> bool:
    return status == 200 and "Apache Server Status" in body


@dataclass(frozen=True)
class Probe:
    path: str
    title: str
    severity: Severity
    validator: Validator
    fix: str


PROBES: tuple[Probe, ...] = (
    Probe("/.git/HEAD", "Exposed .git directory", Severity.high, _git_head,
          "Block access to /.git and rotate any leaked secrets."),
    Probe("/.env", "Exposed .env file", Severity.high, _dotenv,
          "Remove the file from the web root and rotate every secret it contained."),
    Probe("/phpinfo.php", "phpinfo() page exposed", Severity.medium, _phpinfo,
          "Delete phpinfo pages from production."),
    Probe("/server-status", "Apache server-status exposed", Severity.medium, _server_status,
          "Restrict /server-status to trusted IPs."),
)


def probe_to_finding(probe: Probe, url: str) -> Finding:
    return Finding(check="exposed-files", title=probe.title, severity=probe.severity,
                   detail=url, recommendation=probe.fix)


def check_security_txt(status: int, body: str) -> Finding | None:
    if status == 200 and "contact:" in body.lower():
        return None
    return Finding(check="disclosure", title="No security.txt found", severity=Severity.info,
                   detail="/.well-known/security.txt is missing or has no Contact field",
                   recommendation="Publish a security.txt (RFC 9116) so researchers can report issues.")
