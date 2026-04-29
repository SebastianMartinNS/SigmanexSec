"""Phase 4 dashboard hardening tests.

- Sliding session cookie: refreshed on each authed request, idle expiry,
  absolute-cap enforced via embedded ``iat``.
- Open-redirect helper rejects all known dangerous prefixes.
- Body-limit middleware returns 413 on oversized bodies.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


# ── Open-redirect guard ────────────────────────────────────────────────────
@pytest.mark.parametrize("evil", [
    "http://evil",
    "https://evil",
    "//evil.com/path",
    "///evil.com",
    "////evil",
    "javascript:alert(1)",
    " javascript:alert(1)",  # leading space stripped before scheme detect
    "data:text/html,<script>",
    "vbscript:msgbox",
    "/path\nLocation: http://evil",
    "/path\rfoo",
    "/path\x00",
    "\\\\evil",
    "/path/\\\\evil",
    "",
    None,
    123,
])
def test_safe_next_url_rejects_dangerous(evil):
    from sap_dashboard.backend.security import safe_next_url
    assert safe_next_url(evil, fallback="/") == "/"


@pytest.mark.parametrize("good", [
    "/",
    "/dashboard",
    "/api/runs/abc",
    "/path?x=1&y=2",
    "/path#frag",
])
def test_safe_next_url_accepts_local(good):
    from sap_dashboard.backend.security import safe_next_url
    assert safe_next_url(good) == good


# ── Sliding session ────────────────────────────────────────────────────────
def test_session_idle_expiry(monkeypatch):
    """A token older than SESSION_IDLE_S must fail to verify."""
    import sap_dashboard.backend.security as sec

    monkeypatch.setattr(sec, "SESSION_IDLE_S", 1)
    monkeypatch.setattr(sec, "SESSION_MAX_AGE_S", 3600)
    tok = sec.issue_session("alice")
    assert sec.verify_session(tok) == "alice"
    # itsdangerous uses second-resolution timestamps; sleep > 2s to be safe.
    time.sleep(2.5)
    assert sec.verify_session(tok) is None  # idle expired


def test_session_refresh_preserves_iat(monkeypatch):
    """``refresh_session`` must roll the signature timestamp but keep ``iat``
    so the absolute cap still fires."""
    import sap_dashboard.backend.security as sec

    monkeypatch.setattr(sec, "SESSION_IDLE_S", 60)
    monkeypatch.setattr(sec, "SESSION_MAX_AGE_S", 60)
    # Issue a token with iat 70 seconds in the past — over the absolute cap.
    old_iat = int(time.time()) - 70
    tok = sec.issue_session("alice", iat=old_iat)
    # Idle window is fine but absolute cap is exceeded.
    assert sec.verify_session(tok) is None
    assert sec.refresh_session(tok) is None


def test_session_refresh_rolls_idle_window(monkeypatch):
    import sap_dashboard.backend.security as sec

    monkeypatch.setattr(sec, "SESSION_IDLE_S", 5)
    monkeypatch.setattr(sec, "SESSION_MAX_AGE_S", 3600)
    tok = sec.issue_session("alice")
    refreshed = sec.refresh_session(tok)
    assert refreshed is not None
    # Refreshed token decodes to the same username.
    assert sec.verify_session(refreshed) == "alice"


# ── Body limit middleware ──────────────────────────────────────────────────
def test_body_limit_middleware_413(monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_MAX_BODY_BYTES", "1024")
    monkeypatch.setenv("SAP_DASHBOARD_USER", "test")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "test")
    # Reset cached config / deps state so env takes effect.
    from sap_dashboard.backend import deps
    deps.get_config.cache_clear()
    from fastapi.testclient import TestClient
    from sap_dashboard.backend.app import app

    client = TestClient(app)
    # 2 KiB body, well over the 1 KiB cap.
    r = client.post(
        "/api/auth/login",
        content=b"x" * 2048,
        headers={"Content-Type": "application/json", "Content-Length": "2048"},
    )
    assert r.status_code == 413, r.text


# ── WS auth-frame timeout ─────────────────────────────────────────────────
def test_ws_auth_frame_timeout_constant():
    """Regression guard: the WS auth-frame timeout must be ≤ 5s."""
    from pathlib import Path

    src = (Path(__file__).resolve().parent.parent
           / "sap_dashboard" / "backend" / "routes" / "audit.py").read_text()
    # A trivially-grep-able assertion — we don't want a regression that
    # silently bumps it back to 10s.
    import re
    m = re.search(r"receive_json\(\),\s*timeout=(\d+)", src)
    assert m, "WS auth frame receive_json call not found"
    assert int(m.group(1)) <= 5, f"WS auth-frame timeout regressed to {m.group(1)}s"
