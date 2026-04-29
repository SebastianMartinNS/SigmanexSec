"""P2.3 — RBAC smoke tests for the dashboard backend."""
from __future__ import annotations

import json
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "admin")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DASHBOARD_USERS", json.dumps({
        "viewer1":   {"pass": "viewerpass987654", "role": "viewer"},
        "operator1": {"pass": "operpass123987654", "role": "operator"},
    }))
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


def _login(c, user, pwd):
    r = c.post("/api/auth/login", json={"username": user, "password": pwd})
    assert r.status_code == 200, r.text
    return r.json()


def test_admin_role_in_login_response(client):
    j = _login(client, "admin", "verystrongpass1234")
    assert j["role"] == "admin"


def test_viewer_role_in_login_response(client):
    j = _login(client, "viewer1", "viewerpass987654")
    assert j["role"] == "viewer"


def test_operator_role_in_login_response(client):
    j = _login(client, "operator1", "operpass123987654")
    assert j["role"] == "operator"


def test_viewer_blocked_from_system_reset(client):
    _login(client, "viewer1", "viewerpass987654")
    csrf = client.cookies.get("sap_csrf")
    r = client.post("/api/system/reset",
                    json={"confirm": "WIPE_ALL"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403
    assert "role" in r.json().get("detail", "").lower()


def test_operator_blocked_from_system_reset(client):
    _login(client, "operator1", "operpass123987654")
    csrf = client.cookies.get("sap_csrf")
    r = client.post("/api/system/reset",
                    json={"confirm": "WIPE_ALL"},
                    headers={"X-CSRF-Token": csrf})
    assert r.status_code == 403


def test_admin_allowed_into_system_reset(client):
    _login(client, "admin", "verystrongpass1234")
    csrf = client.cookies.get("sap_csrf")
    r = client.post("/api/system/reset",
                    json={"confirm": "WIPE_ALL"},
                    headers={"X-CSRF-Token": csrf})
    # Admin must pass the role check; whatever the route returns next must
    # not be a 401/403.
    assert r.status_code not in (401, 403), r.text


def test_unknown_user_rejected(client):
    r = client.post("/api/auth/login",
                    json={"username": "ghost", "password": "whatever987654"})
    assert r.status_code == 401
