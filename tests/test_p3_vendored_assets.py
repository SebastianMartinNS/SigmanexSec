"""P3.2 + P3.3 — vendored assets, SRI, no CDN, Trusted Types report-only."""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
FRONTEND = REPO / "sap_dashboard" / "frontend"
VENDOR = FRONTEND / "vendor"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    monkeypatch.setenv("SAP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "assess.db"))
    monkeypatch.setenv("SAP_RATE_LIMIT_DB", str(tmp_path / "rl.db"))
    from core.rate_limiter import reset_rate_limiter_for_tests
    reset_rate_limiter_for_tests()
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    from sap_dashboard.backend.app import app
    c = TestClient(app)
    # The dashboard (which references app.js with SRI) is now behind auth;
    # log in so GET / renders the authenticated shell.
    r = c.post("/api/auth/login",
               json={"username": "u", "password": "verystrongpass1234"})
    assert r.status_code == 200, r.text
    return c


def _sri(path: Path) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(path.read_bytes()).digest()
    ).decode()


def test_no_cdn_in_csp(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    for cdn in ("unpkg.com", "cdn.tailwindcss.com", "cdnjs", "jsdelivr"):
        assert cdn not in csp, f"CSP still allows CDN {cdn}: {csp}"


def test_no_cdn_in_html(client):
    body = client.get("/").text
    assert "unpkg.com" not in body
    assert "cdn.tailwindcss.com" not in body


def test_style_src_self_only_cdn_blocked(client):
    """Inline styles are tolerated for Alpine x-show/x-transition (cannot
    exfiltrate or execute), but no remote stylesheet origin must be
    allowed: only 'self' (vendored) plus 'unsafe-inline'.
    """
    csp = client.get("/").headers["Content-Security-Policy"]
    style = re.search(r"style-src([^;]*);", csp).group(1).strip()
    tokens = set(style.split())
    assert tokens <= {"'self'", "'unsafe-inline'"}, style
    assert "'self'" in tokens, style


def test_vendor_assets_served_from_local_mount(client):
    for f in ("htmx.min.js", "alpine.min.js", "tailwind.css", "app.js"):
        r = client.get(f"/vendor/{f}")
        assert r.status_code == 200, f
        # Content must hash to the SRI advertised in index.html.
        actual = "sha256-" + base64.b64encode(
            hashlib.sha256(r.content).digest()
        ).decode()
        html = client.get("/").text
        m = re.search(
            r'(?:href|src)="/vendor/' + re.escape(f) + r'"\s+integrity="([^"]+)"',
            html, re.DOTALL,
        )
        assert m, f"no integrity attribute for {f} in index.html"
        assert m.group(1) == actual, (
            f"{f}: SRI mismatch in index.html "
            f"(html={m.group(1)} vs disk={actual})"
        )


def test_no_inline_script_or_style_in_html(client):
    body = client.get("/").text
    # Inline <script>...</script> blocks (no src=) must not exist.
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>[^<]*\S", body), \
        "inline <script> still present"
    assert "<style" not in body, "inline <style> still present"


def test_trusted_types_report_only_header_present(client):
    h = client.get("/").headers
    rep = h.get("Content-Security-Policy-Report-Only", "")
    assert "require-trusted-types-for 'script'" in rep
    assert "trusted-types default" in rep
