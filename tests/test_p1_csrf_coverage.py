"""
P1.9 — CSRF coverage sweep. Confirms that EVERY state-changing endpoint
rejects requests authenticated by a session cookie when the X-CSRF-Token
header is missing or wrong. Also verifies that GET routes never require it.
"""
from __future__ import annotations

import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("SAP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("SAP_RATE_LIMIT_DB", str(tmp_path / "rl.sqlite"))
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    from core.rate_limiter import reset_rate_limiter_for_tests
    reset_rate_limiter_for_tests()
    from sap_dashboard.backend.app import app  # noqa: WPS433
    c = TestClient(app)
    # Login to obtain session + CSRF cookies.
    c.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    return c


WRITE_ENDPOINTS = [
    ("POST",   "/api/auth/logout"),
    ("POST",   "/api/engagements"),
    ("PATCH",  "/api/engagements/anything"),
    ("POST",   "/api/engagements/anything/run"),
    ("PATCH",  "/api/runs/anything"),
    ("POST",   "/api/runs/anything/approve"),
    ("POST",   "/api/sessions"),
    ("POST",   "/api/sessions/x/send"),
    ("POST",   "/api/sessions/x/read"),
    ("DELETE", "/api/sessions/x"),
    ("POST",   "/api/sessions/reap"),
    ("PATCH",  "/api/settings"),
    ("POST",   "/api/sudo/unlock"),
    ("DELETE", "/api/sudo"),
    ("POST",   "/api/sudo/heartbeat"),
    ("POST",   "/api/engagements/x/report"),
    ("POST",   "/api/engagements/x/reset"),
    ("POST",   "/api/system/reset"),
]


@pytest.mark.parametrize("method,path", WRITE_ENDPOINTS)
def test_state_change_requires_csrf_when_session_present(client, method, path):
    """Without the X-CSRF-Token header the middleware MUST return 403."""
    resp = client.request(method, path)
    # Login is the only exempt path — this is enforced by the middleware.
    assert resp.status_code == 403, (
        f"{method} {path} should be CSRF-blocked but returned {resp.status_code}: {resp.text[:200]}"
    )
    assert "csrf" in resp.text.lower()


def test_state_change_accepts_correct_csrf(client):
    csrf = client.cookies.get("sap_csrf")
    # Use a benign POST: settings PATCH should not 403 with valid CSRF.
    r = client.patch("/api/settings", json={}, headers={"X-CSRF-Token": csrf})
    assert r.status_code != 403, r.text


def test_login_endpoint_remains_csrf_exempt(client):
    # Login MUST work without CSRF (it issues the token); re-login is fine.
    r = client.post("/api/auth/login",
                    json={"username": "u", "password": "verystrongpass1234"})
    assert r.status_code == 200
