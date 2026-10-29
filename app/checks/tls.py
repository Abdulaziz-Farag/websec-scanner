from __future__ import annotations

import socket
import ssl
import time

from app.schemas import Finding, Severity


def evaluate_cert(not_after_ts: float, now: float, version: str | None) -> list[Finding]:
    days = int((not_after_ts - now) // 86400)
    out: list[Finding] = []
    if days < 0:
        out.append(Finding(check="tls", title="Certificate expired", severity=Severity.high,
                           detail=f"Expired {-days} day(s) ago",
                           recommendation="Renew the certificate immediately."))
    elif days < 14:
        out.append(Finding(check="tls", title="Certificate expires very soon", severity=Severity.high,
                           detail=f"{days} day(s) left", recommendation="Renew the certificate."))
    elif days < 30:
        out.append(Finding(check="tls", title="Certificate expires soon", severity=Severity.medium,
                           detail=f"{days} day(s) left", recommendation="Plan renewal / automate it."))
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(Finding(check="tls", title="Outdated TLS protocol", severity=Severity.high,
                           detail=f"Negotiated {version}", recommendation="Require TLS 1.2+."))
    return out


def inspect_tls(host: str, port: int = 443, timeout: float = 6.0) -> list[Finding]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        return [Finding(check="tls", title="Certificate verification failed",
                        severity=Severity.high, detail=str(exc.verify_message),
                        recommendation="Serve a valid certificate that matches the hostname.")]
    except (OSError, ssl.SSLError) as exc:
        return [Finding(check="tls", title="TLS connection failed", severity=Severity.info,
                        detail=type(exc).__name__)]
    findings = evaluate_cert(ssl.cert_time_to_seconds(cert["notAfter"]), time.time(), version)
    findings.append(Finding(check="tls", title="TLS negotiated", severity=Severity.info,
                            detail=str(version)))
    return findings
