"""P3.1 — CSP nonce + tightened script-src."""
from __future__ import annotations

import re
import sys

import pytest
from fastapi.testclient import TestClient


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
    return TestClient(app)


def test_csp_includes_nonce_on_script_src(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    m = re.search(r"script-src[^;]*'nonce-([A-Za-z0-9_-]{16,})'", csp)
    assert m, f"no script-src nonce in CSP: {csp}"


def test_csp_drops_unsafe_inline_on_script_src(client):
    r = client.get("/")
    csp = r.headers.get("Content-Security-Policy", "")
    # script-src clause must NOT contain 'unsafe-inline'
    script_src = re.search(r"script-src([^;]*);", csp)
    assert script_src, csp
    assert "'unsafe-inline'" not in script_src.group(1), csp


def test_csp_nonce_changes_per_request(client):
    a = client.get("/").headers.get("Content-Security-Policy", "")
    b = client.get("/").headers.get("Content-Security-Policy", "")
    n_a = re.search(r"'nonce-([A-Za-z0-9_-]{16,})'", a).group(1)
    n_b = re.search(r"'nonce-([A-Za-z0-9_-]{16,})'", b).group(1)
    assert n_a != n_b


def test_inline_scripts_carry_nonce(client):
    r = client.get("/")
    csp = r.headers["Content-Security-Policy"]
    nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp).group(1)
    body = r.text
    # All non-self-closing <script> opening tags must carry our nonce.
    inline = re.findall(r"<script(?![^>]*\bnonce=)[^>]*>", body)
    # `inline` should be empty: every script tag was rewritten with nonce.
    assert inline == [], f"these <script> tags lack the nonce: {inline}"
    # Spot-check at least one tag has the right nonce.
    assert f'nonce="{nonce}"' in body


def test_security_headers_present(client):
    r = client.get("/")
    h = r.headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "no-referrer"
    csp = h.get("Content-Security-Policy", "")
    for clause in ("default-src 'self'", "frame-ancestors 'none'",
                   "base-uri 'none'", "object-src 'none'"):
        assert clause in csp, f"missing CSP clause: {clause}"
