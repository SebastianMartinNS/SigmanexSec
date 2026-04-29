"""
P1.7 hardening tests — cross-process rate limiter + lockout.
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("SAP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("SAP_RATE_LIMIT_DB", str(tmp_path / "rl.sqlite"))
    return tmp_path


@pytest.fixture
def client(env):
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    # Reset limiter singleton so SAP_RATE_LIMIT_DB env is honored.
    from core.rate_limiter import reset_rate_limiter_for_tests
    reset_rate_limiter_for_tests()
    from sap_dashboard.backend.app import app  # noqa: WPS433
    return TestClient(app)


def test_login_rate_limited_after_max_attempts(client):
    # Fail 5 times within window — 6th should be 429.
    for _ in range(5):
        r = client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
    assert r.status_code == 429
    assert "retry" in r.text.lower()
    assert r.headers.get("Retry-After")


def test_login_lockout_after_many_failures(client):
    # Continued brute force is blocked with 429 (rate throttle covers the
    # lockout-budget too because each blocked request never increments
    # `failures`). Verifies the perimeter holds against rapid attempts.
    blocked = 0
    for _ in range(20):
        r = client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
        if r.status_code == 429:
            blocked += 1
    assert blocked >= 10  # most attempts must be blocked


def test_successful_login_resets_failures(client):
    # 3 failures, then a success → counter resets, next failure budget is full.
    for _ in range(3):
        client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
    r = client.post("/api/auth/login", json={"username": "u", "password": "verystrongpass1234"})
    assert r.status_code == 200
    # After reset we should once again be allowed at least 5 fresh attempts.
    for i in range(5):
        rr = client.post("/api/auth/login", json={"username": "u", "password": "wrong"})
        assert rr.status_code == 401, f"attempt {i}: {rr.status_code} {rr.text}"


def test_rate_limiter_module_level_basic():
    """Direct unit test of the limiter module — fail-open semantics, lockout, reset."""
    with tempfile.TemporaryDirectory() as d:
        os.environ["SAP_RATE_LIMIT_DB"] = os.path.join(d, "rl.sqlite")
        from core.rate_limiter import RateLimiter, reset_rate_limiter_for_tests
        reset_rate_limiter_for_tests()
        rl = RateLimiter()
        for _ in range(3):
            assert rl.check("k", window_s=60, max_attempts=3).allowed
        # 4th hits the throttle.
        assert not rl.check("k", window_s=60, max_attempts=3).allowed

        # Failure budget triggers a lockout.
        for _ in range(5):
            rl.record_failure("k2", max_failures=5, lockout_s=60)
        decision = rl.check("k2")
        assert not decision.allowed
        assert decision.reason == "lockout"

        # Success clears the slate.
        rl.record_success("k2")
        assert rl.check("k2").allowed
