from __future__ import annotations

from html import escape

from app.schemas import ScanResult

_CSS = """
body{font-family:system-ui,sans-serif;background:#0b1220;color:#e6edf6;margin:0;padding:1rem}
.wrap{max-width:760px;margin:auto}h1{font-size:1.3rem}
.score{font-size:2.4rem;font-weight:700;color:#22d3ee}
table{width:100%;border-collapse:collapse;margin-top:1rem}
td{padding:.6rem;border-bottom:1px solid #1e293b;vertical-align:top}
small{color:#94a3b8;word-break:break-all}
.sev{padding:.15rem .5rem;border-radius:6px;font-size:.75rem;font-weight:700;text-transform:uppercase}
.high{background:#ef4444}.medium{background:#f59e0b;color:#111}.low{background:#3b82f6}.info{background:#475569}
"""


def render_html(result: ScanResult) -> str:
    """Every value coming from the scanned site is escaped: headers are attacker-controlled."""
    rows = []
    for f in result.findings:
        rec = f"<br><small>Fix: {escape(f.recommendation)}</small>" if f.recommendation else ""
        rows.append(
            f"<tr><td><span class='sev {escape(f.severity.value)}'>{escape(f.severity.value)}</span></td>"
            f"<td><b>{escape(f.title)}</b><br><small>{escape(f.detail)}</small>{rec}</td></tr>"
        )
    counts = " · ".join(f"{escape(k)}: {v}" for k, v in result.summary.items())
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>WebSec report - {escape(result.target)}</title><style>{_CSS}</style></head>"
        f"<body><div class='wrap'><h1>WebSec report: {escape(result.target)}</h1>"
        f"<div class='score'>{result.score}/100</div><small>{counts} · {result.duration_ms} ms</small>"
        f"<table>{''.join(rows)}</table></div></body></html>"
    )
