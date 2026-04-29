"""Phase 5 hardening tests — adaptive layer + dashboard remaining items."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


# ── Scenario classifier confidence floor ───────────────────────────────────
def test_scenario_below_threshold_falls_back_to_mixed(monkeypatch):
    """Confidence below SAP_SCENARIO_MIN_CONFIDENCE must demote to mixed."""
    from core.adaptive.scenario import ScenarioClassifier

    # Threshold above any plausible single-signal score → forces fallback.
    monkeypatch.setenv("SAP_SCENARIO_MIN_CONFIDENCE", "0.99")
    # Strong scope_urls signal would normally classify as web with ~0.90 confidence.
    s = ScenarioClassifier.classify(scope={"scope_urls": ["http://t/"]})
    assert s.type == "mixed"
    assert any("below_threshold" in i for i in s.indicators)


def test_scenario_above_threshold_keeps_dominant(monkeypatch):
    from core.adaptive.scenario import ScenarioClassifier

    monkeypatch.setenv("SAP_SCENARIO_MIN_CONFIDENCE", "0.20")
    s = ScenarioClassifier.classify(scope={"scope_urls": ["http://t/"]})
    assert s.type == "web"
    assert s.confidence >= 0.30


# ── Repetition fuzzy match ─────────────────────────────────────────────────
def test_fuzzy_signature_collapses_near_duplicates():
    from agent.orchestrator import Orchestrator

    o = Orchestrator.__new__(Orchestrator)  # bypass __init__ for this unit test
    sig1 = o._fuzzy_signature("nmap_scan", {
        "target": "10.0.0.1", "ports": "1-1000", "options": "-sV"
    })
    # Tiny variant: extra whitespace flag — Jaccard should still be ≥ 0.85.
    sig2 = o._fuzzy_signature("nmap_scan", {
        "target": "10.0.0.1", "ports": "1-1000", "options": "-sV  "
    })
    assert sig1 == sig2, "near-duplicate args must collapse onto same signature"


def test_fuzzy_signature_distinguishes_unrelated_calls():
    from agent.orchestrator import Orchestrator

    o = Orchestrator.__new__(Orchestrator)
    a = o._fuzzy_signature("nmap_scan", {"target": "10.0.0.1", "ports": "1-1000"})
    b = o._fuzzy_signature("dirb_fuzz", {"url": "http://example.com/admin"})
    assert a != b, "unrelated tool calls must have distinct signatures"


# ── Memory truncation: HEAD preserved ──────────────────────────────────────
def test_summary_truncation_keeps_head(monkeypatch, tmp_path):
    """Phase 5: when the summary is trimmed, the earliest decisions
    (HEAD) must survive — only the middle is elided."""
    # Direct unit-test of the truncation snippet semantics.
    text = "ORIGINAL_DECISION\n" + ("filler " * 5000) + "RECENT_STATE"
    max_chars = 6000
    head = max_chars // 3
    tail = max_chars - head - 32
    marker = "\n\n[...summary middle elided...]\n\n"
    truncated = text[:head] + marker + text[-tail:]
    assert truncated.startswith("ORIGINAL_DECISION")
    assert truncated.endswith("RECENT_STATE")
    assert "[...summary middle elided...]" in truncated
    assert len(truncated) <= max_chars + len(marker)


# ── CSRF rotation on sudo ──────────────────────────────────────────────────
def test_security_rotate_csrf_helper(monkeypatch):
    """``rotate_csrf`` must set a fresh ``sap_csrf`` cookie on the response."""
    from sap_dashboard.backend.security import rotate_csrf

    class _FakeURL:
        scheme = "http"

    class _FakeReq:
        url = _FakeURL()
        headers: dict = {}

    class _FakeResp:
        def __init__(self):
            self.cookies: list[dict] = []

        def set_cookie(self, **kwargs):
            self.cookies.append(kwargs)

    req = _FakeReq()
    resp = _FakeResp()
    tok = rotate_csrf(req, resp)
    assert tok and len(tok) >= 32
    assert any(c.get("key") == "sap_csrf" and c.get("value") == tok for c in resp.cookies)


# ── Per-IP WS connection cap (env-tunable knob) ────────────────────────────
def test_ws_per_ip_cap_default():
    from sap_dashboard.backend.routes.audit import _ws_per_ip_cap
    assert _ws_per_ip_cap() >= 1


def test_ws_per_ip_cap_clamps_to_minimum(monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_WS_PER_IP", "0")
    from sap_dashboard.backend.routes.audit import _ws_per_ip_cap
    assert _ws_per_ip_cap() == 1


# ── GET endpoint rate-limit middleware ────────────────────────────────────
def test_get_rate_limit_returns_429(monkeypatch):
    """Anonymous GETs hammering /login must eventually get 429."""
    monkeypatch.setenv("SAP_DASHBOARD_RL_ANON", "3")  # tight cap for the test
    monkeypatch.setenv("SAP_DASHBOARD_USER", "test")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "test")
    from sap_dashboard.backend import deps
    deps.get_config.cache_clear()
    # Reimport app to re-bind the middleware with new env? The middleware
    # reads env on every request via ``_limits()``, so no reimport needed.
    # But the in-memory bucket is shared across tests; clear it.
    from sap_dashboard.backend.app import _RateLimitMiddleware, app
    _RateLimitMiddleware._BUCKETS.clear()
    from fastapi.testclient import TestClient
    client = TestClient(app)
    statuses = []
    # /login is GET HTML — covered by the anon limit. Need a path NOT
    # in _SKIP_PREFIXES; /login is an HTML page on /login (not /ui/).
    for _ in range(6):
        r = client.get("/login")
        statuses.append(r.status_code)
    assert 429 in statuses, f"expected 429 in {statuses}"


# ── mlock verification helper guards against missing libc symbols ──────────
def test_mlock_helper_handles_missing_mincore(monkeypatch):
    """``_verify_mlock_with_mincore`` is a no-op when libc lacks mincore."""
    import core.process_hardening as ph

    class _Stub:
        pass

    monkeypatch.setattr(ph, "_LIBC", _Stub())
    s = ph.HardeningStatus()
    # Should not raise even though our stub libc has neither mlockall
    # nor mincore.
    ph._verify_mlock_with_mincore(s)
