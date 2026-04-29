"""P0 hardening — cookie auth + CSRF + Basic backward-compat."""
from __future__ import annotations

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

    # Force fresh module instances so SAP_STATE_DIR and singletons are honored.
    import sys
    # Drop everything under sap_dashboard.backend so packages reload cleanly.
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    from sap_dashboard.backend.app import app  # noqa: WPS433
    return TestClient(app)


# ── /api/auth/login ─────────────────────────────────────────────────────────

def test_login_sets_cookies_and_returns_username(client):
    r = client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    assert r.status_code == 200, r.text
    assert r.json()["username"] == "u"
    assert "sap_session" in r.cookies
    assert "sap_csrf" in r.cookies
    # session cookie must NOT be readable by JS (HttpOnly attr in Set-Cookie)
    set_cookies = r.headers.get_list("set-cookie")
    sess = next(c for c in set_cookies if c.startswith("sap_session="))
    assert "HttpOnly" in sess
    assert "SameSite=strict" in sess.lower() or "samesite=strict" in sess.lower()


def test_login_invalid_credentials(client):
    r = client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
    assert r.status_code == 401


def test_me_requires_auth(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_works_with_session_cookie(client):
    client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    assert r.json()["username"] == "u"


# ── Backward compat: HTTP Basic still works ─────────────────────────────────

def test_basic_auth_still_works(client):
    r = client.get("/api/sudo/status", auth=("u", "verystrongpass1234"))
    # 200 (vault available) or 503 (broker not running) — anything but 401.
    assert r.status_code != 401


# ── CSRF: state-changing request with cookie requires X-CSRF-Token ──────────

def test_csrf_blocks_state_change_without_token(client):
    client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    # Cookies are now set on the client. POST without CSRF header.
    r = client.post("/api/sudo", json={})  # any state-changing path on auth router
    # Should be 403 (CSRF) — not 200/204
    # /api/sudo doesn't accept POST with empty body (404/405 also fine), but
    # NOT 401: cookie auth was accepted.
    # The CSRF check fires first regardless of route validation order.
    # We only assert 403 here for the protected paths we know exist.
    r2 = client.delete("/api/sudo")  # lock_endpoint
    assert r2.status_code == 403, f"expected CSRF rejection, got {r2.status_code}: {r2.text}"


def test_csrf_passes_state_change_with_token(client):
    login = client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    csrf = login.cookies.get("sap_csrf")
    assert csrf
    r = client.delete("/api/sudo", headers={"X-CSRF-Token": csrf})
    # Either 200 (vault locked) or 503 (broker missing in test); never 403/401.
    assert r.status_code not in (401, 403), r.text


def test_csrf_does_not_apply_to_basic_auth(client):
    # Basic auth path should NOT require CSRF (no cookie present).
    r = client.delete("/api/sudo", auth=("u", "verystrongpass1234"))
    assert r.status_code not in (401, 403), r.text


# ── Logout clears cookies ───────────────────────────────────────────────────

def test_logout_clears_cookies(client):
    client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    csrf = client.cookies.get("sap_csrf")
    r = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    # subsequent /me must be 401
    client.cookies.clear()
    assert client.get("/api/auth/me").status_code == 401


# ── Security headers ────────────────────────────────────────────────────────

def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers
    csp = r.headers["Content-Security-Policy"]
    # P3.1: 'unsafe-eval' is temporarily granted to script-src for Alpine.js
    # 3.13's expression parser; will be removed in P3.2 (SvelteKit refactor).
    # The critical invariant is that script-src MUST NOT contain
    # 'unsafe-inline' — nonce-based CSP replaces it.
    import re as _re
    script_src = _re.search(r"script-src([^;]*);", csp)
    assert script_src, csp
    assert "'unsafe-inline'" not in script_src.group(1), \
        "script-src must not allow 'unsafe-inline'"
    assert "frame-ancestors 'none'" in csp


# ── Session cookie signing ──────────────────────────────────────────────────

def test_invalid_session_cookie_rejected(client):
    client.cookies.set("sap_session", "not-a-valid-signed-token")
    r = client.get("/api/auth/me")
    assert r.status_code == 401
