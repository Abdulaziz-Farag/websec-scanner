from __future__ import annotations

import re
from collections.abc import Mapping

from app.schemas import Finding, Severity

_VERSIONED = re.compile(r"\d+\.\d+")


def analyze_headers(headers: Mapping[str, str], is_https: bool) -> list[Finding]:
    h = {k.lower(): v for k, v in headers.items()}
    out: list[Finding] = []

    def missing(name: str, sev: Severity, why: str, fix: str) -> None:
        out.append(Finding(check="headers", title=f"Missing {name}", severity=sev,
                           detail=why, recommendation=fix))

    if is_https and "strict-transport-security" not in h:
        missing("Strict-Transport-Security", Severity.medium,
                "Browsers are not told to enforce HTTPS.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    csp = h.get("content-security-policy")
    if csp is None:
        missing("Content-Security-Policy", Severity.medium,
                "No CSP: injected scripts run unrestricted.",
                "Define a restrictive Content-Security-Policy.")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing("X-Content-Type-Options", Severity.low,
                "MIME sniffing is not disabled.", "Add: X-Content-Type-Options: nosniff")
    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp.lower()):
        missing("clickjacking protection", Severity.medium,
                "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.")
    if "referrer-policy" not in h:
        missing("Referrer-Policy", Severity.low,
                "Full URLs may leak to third parties.",
                "Add: Referrer-Policy: strict-origin-when-cross-origin")

    server = h.get("server", "")
    if _VERSIONED.search(server):
        out.append(Finding(check="headers", title="Server version disclosed",
                           severity=Severity.low, detail=f"Server: {server}",
                           recommendation="Hide version details from the Server header."))
    if "x-powered-by" in h:
        out.append(Finding(check="headers", title="Technology disclosed via X-Powered-By",
                           severity=Severity.low, detail=f"X-Powered-By: {h['x-powered-by']}",
                           recommendation="Remove the X-Powered-By header."))
    return out


def analyze_cookies(set_cookie_headers: list[str], is_https: bool) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        flags = raw.lower()
        problems = []
        if is_https and "secure" not in flags:
            problems.append("Secure")
        if "httponly" not in flags:
            problems.append("HttpOnly")
        if "samesite" not in flags:
            problems.append("SameSite")
        if problems:
            out.append(Finding(check="cookies", title=f"Cookie '{name}' lacks {', '.join(problems)}",
                               severity=Severity.low,
                               recommendation="Set Secure, HttpOnly and SameSite on session cookies."))
    return out
