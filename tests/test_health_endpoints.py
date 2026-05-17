"""Tests for the dashboard liveness (/healthz) and readiness (/readyz) probes."""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def dashboard_app(tmp_path, monkeypatch):
    """Spin up the dashboard FastAPI app with isolated state for each test."""
    # Provide credentials so deps._expected_creds() does not raise 503.
    monkeypatch.setenv("SAP_DASHBOARD_USER", "tester")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p4ssw0rd")
    monkeypatch.setenv("SAP_SESSION_SECRET", "x" * 64)

    # Point session db and audit log at fresh, writable paths.
    session_db = tmp_path / "sessions" / "assessments.db"
    session_db.parent.mkdir(parents=True, exist_ok=True)
    audit_log = tmp_path / "logs" / "audit.jsonl"
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SESSION_DB_PATH", str(session_db))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_log))

    # The sudo broker is opt-in; default tests should not require it.
    monkeypatch.delenv("SAP_SUDO_BROKER_ENABLED", raising=False)
    monkeypatch.delenv("SAP_SUDO_SOCKET", raising=False)

    # Create a real (but empty) sqlite file so /readyz succeeds.
    import sqlite3
    with sqlite3.connect(str(session_db)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS _probe (id INTEGER PRIMARY KEY)")
        conn.commit()

    from fastapi.testclient import TestClient

    from sap_dashboard.backend.app import app

    return TestClient(app)


def test_healthz_returns_200_and_uptime(dashboard_app):
    response = dashboard_app.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "uptime_seconds" in body
    assert body["uptime_seconds"] >= 0


def test_healthz_does_not_require_auth(dashboard_app):
    """k8s probes are unauthenticated; /healthz must respond without creds."""
    response = dashboard_app.get("/healthz")
    assert response.status_code == 200


def test_readyz_returns_200_when_all_checks_pass(dashboard_app):
    response = dashboard_app.get("/readyz")
    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    checks = body["checks"]
    assert checks["session_db"]["ok"] is True
    assert checks["audit_log_dir"]["ok"] is True
    # Sudo broker not configured → skipped, reported as ok.
    assert checks["sudo_broker_socket"]["ok"] is True
    assert checks["sudo_broker_socket"].get("skipped") is True


def test_readyz_returns_503_when_session_db_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "tester")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p4ssw0rd")
    monkeypatch.setenv("SAP_SESSION_SECRET", "x" * 64)
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "does-not-exist.db"))
    audit_log = tmp_path / "logs" / "audit.jsonl"
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_log))

    from fastapi.testclient import TestClient

    from sap_dashboard.backend.app import app

    client = TestClient(app)
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["checks"]["session_db"]["ok"] is False
    assert body["checks"]["session_db"]["reason"] == "missing"


def test_readyz_returns_503_when_audit_dir_unwritable(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "tester")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p4ssw0rd")
    monkeypatch.setenv("SAP_SESSION_SECRET", "x" * 64)
    session_db = tmp_path / "sessions" / "s.db"
    session_db.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3
    with sqlite3.connect(str(session_db)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS _probe (id INTEGER)")
        conn.commit()
    monkeypatch.setenv("SESSION_DB_PATH", str(session_db))

    audit_dir = tmp_path / "logs-readonly"
    audit_dir.mkdir()
    audit_path = audit_dir / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_path))
    os.chmod(audit_dir, 0o555)  # noqa: S103 — intentional read-only dir to drive a 503 from /readyz
    try:
        from fastapi.testclient import TestClient

        from sap_dashboard.backend.app import app

        client = TestClient(app)
        response = client.get("/readyz")
        assert response.status_code == 503
        body = response.json()
        assert body["ready"] is False
        assert body["checks"]["audit_log_dir"]["ok"] is False
    finally:
        os.chmod(audit_dir, 0o755)  # noqa: S103 — restore writable perms so pytest tmp cleanup succeeds


def test_readyz_includes_sudo_socket_check_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "tester")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p4ssw0rd")
    monkeypatch.setenv("SAP_SESSION_SECRET", "x" * 64)
    session_db = tmp_path / "sessions" / "s.db"
    session_db.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3
    with sqlite3.connect(str(session_db)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS _probe (id INTEGER)")
        conn.commit()
    monkeypatch.setenv("SESSION_DB_PATH", str(session_db))
    audit_log = tmp_path / "logs" / "audit.jsonl"
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit_log))

    # Point the broker at a non-existent path; readyz should report 503.
    monkeypatch.setenv("SAP_SUDO_BROKER_ENABLED", "1")
    monkeypatch.setenv("SAP_SUDO_SOCKET", str(tmp_path / "no-such-socket"))

    from fastapi.testclient import TestClient

    from sap_dashboard.backend.app import app

    client = TestClient(app)
    response = client.get("/readyz")
    assert response.status_code == 503
    body = response.json()
    assert body["checks"]["sudo_broker_socket"]["ok"] is False
    assert body["checks"]["sudo_broker_socket"].get("skipped") is None


def test_healthz_and_readyz_skip_rate_limit(dashboard_app):
    """Probes must not burn the per-IP rate-limit bucket."""
    # 60 calls in quick succession — would trip anon limit (30/min default)
    # if rate-limit middleware did not exempt these paths.
    for _ in range(60):
        assert dashboard_app.get("/healthz").status_code == 200
    response = dashboard_app.get("/readyz")
    assert response.status_code == 200
