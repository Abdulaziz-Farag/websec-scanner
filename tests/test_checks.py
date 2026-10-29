import time

from app.checks import exposed, headers, tls
from app.schemas import Severity

GOOD = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def titles(findings):
    return {f.title for f in findings}


def test_missing_headers_are_reported():
    t = titles(headers.analyze_headers({}, is_https=True))
    assert "Missing Strict-Transport-Security" in t
    assert "Missing Content-Security-Policy" in t
    assert "Missing clickjacking protection" in t


def test_hsts_not_required_over_http():
    assert "Missing Strict-Transport-Security" not in titles(headers.analyze_headers({}, is_https=False))


def test_good_headers_have_no_findings():
    assert headers.analyze_headers(GOOD, is_https=True) == []


def test_version_disclosure():
    f = headers.analyze_headers({**GOOD, "Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}, True)
    assert titles(f) == {"Server version disclosed", "Technology disclosed via X-Powered-By"}


def test_cookie_flags():
    f = headers.analyze_cookies(["sid=1", "ok=1; Secure; HttpOnly; SameSite=Lax"], is_https=True)
    assert len(f) == 1 and "Secure, HttpOnly, SameSite" in f[0].title


def test_git_head_validator():
    assert exposed._git_head(200, "text/plain", "ref: refs/heads/main\n")
    assert not exposed._git_head(200, "text/html", "<html>not found</html>")


def test_dotenv_validator_rejects_html_pages():
    assert exposed._dotenv(200, "text/plain", "DB_PASS=x\nAPI_KEY=y\n")
    assert not exposed._dotenv(200, "text/html", "DB_PASS=x\nAPI_KEY=y\n")
    assert not exposed._dotenv(404, "text/plain", "DB_PASS=x")


def test_security_txt():
    assert exposed.check_security_txt(200, "Contact: mailto:sec@example.com") is None
    assert exposed.check_security_txt(404, "").severity == Severity.info


def test_certificate_expiry_levels():
    now = time.time()
    day = 86400
    assert tls.evaluate_cert(now - day, now, "TLSv1.3")[0].title == "Certificate expired"
    assert tls.evaluate_cert(now + 5 * day, now, "TLSv1.3")[0].severity == Severity.high
    assert tls.evaluate_cert(now + 20 * day, now, "TLSv1.3")[0].severity == Severity.medium
    assert tls.evaluate_cert(now + 90 * day, now, "TLSv1.3") == []
    assert tls.evaluate_cert(now + 90 * day, now, "TLSv1")[0].title == "Outdated TLS protocol"
