"""Smoke test for the orchestrator helpers that don't need a live LLM."""
from __future__ import annotations

import pytest

from agent.orchestrator import Orchestrator
from core.adaptive import (
    AdaptiveSettings,
    RepetitionHandler,
    RolloutMode,
)


def test_truncate_for_callback_passthrough():
    short = "x" * 100
    assert Orchestrator._truncate_for_callback(short) == short


def test_truncate_for_callback_caps(monkeypatch):
    import agent.orchestrator as orch

    monkeypatch.setattr(orch, "_CALLBACK_RESULT_CAP", 50)
    text = "x" * 500
    out = Orchestrator._truncate_for_callback(text)
    assert "[truncated" in out
    assert len(out) < len(text)


def test_tool_call_signature_stable():
    s1 = Orchestrator._tool_call_signature("nmap", {"target": "10.0.0.1", "ports": "80,443"})
    s2 = Orchestrator._tool_call_signature("nmap", {"ports": "80,443", "target": "10.0.0.1"})
    s3 = Orchestrator._tool_call_signature("nmap", {"target": "10.0.0.2"})
    assert s1 == s2  # order-independent
    assert s1 != s3


# ── Phase-4 anti-monotony hooks ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "args, expected",
    [
        ({"target": "10.0.0.1"}, "10.0.0.1"),
        ({"url": "https://example.com"}, "https://example.com"),
        ({"host": "dc01.lab", "port": 445}, "dc01.lab"),
        ({"engagement_id": "eng_123"}, "eng_123"),
        ({"random": "x"}, "-"),
        ("not-a-dict", "-"),
    ],
)
def test_extract_target(args, expected):
    assert Orchestrator._extract_target(args) == expected


def test_summarize_result_for_tactic_strips_and_truncates():
    long_text = ("a" * 250) + "\nmore"
    out = Orchestrator._summarize_result_for_tactic(long_text)
    assert "\n" not in out
    # Head+tail summary: 100 head + " … " + 100 tail = 203 chars
    assert len(out) <= 210
    assert out.startswith("a" * 50)
    assert "more" in out


def _make_orchestrator(monkeypatch):
    """Build an orchestrator with no real registry / memory side-effects."""

    async def _noop_build(self):
        return None

    monkeypatch.setattr(
        "agent.orchestrator.ToolRegistry.build", _noop_build, raising=True
    )
    captured: list[tuple[str, str]] = []
    agent = Orchestrator(on_message=lambda role, text: captured.append((role, text)))
    agent._engagement_id = "eng_test"
    return agent, captured


@pytest.mark.asyncio
async def test_maybe_pivot_returns_none_when_adaptive_off(monkeypatch):
    agent, _ = _make_orchestrator(monkeypatch)
    # Default state: _adaptive_settings is None.
    out = await agent._maybe_pivot("nmap_scan", {"target": "10.0.0.1"}, last_result="timeout")
    assert out is None


@pytest.mark.asyncio
async def test_maybe_pivot_emits_suggestion_when_active(monkeypatch):
    agent, captured = _make_orchestrator(monkeypatch)
    agent._adaptive_settings = AdaptiveSettings(
        enabled=True,
        rollout_mode=RolloutMode.ENFORCE,
        auto_pivot=True,
        max_pivots_per_run=3,
    )
    agent._repetition_handler = RepetitionHandler(max_pivots=3)
    payload = await agent._maybe_pivot(
        "nmap_scan",
        {"target": "10.0.0.1"},
        last_result="connection timed out",
    )
    assert payload is not None
    assert payload["suggested_tool"] == "masscan_scan"
    assert payload["fallback_kind"] == "family"
    assert payload["failure_class"] == "timeout"
    # The dashboard saw a decision event for the pivot.
    assert any(
        role == "decision" and "repetition_pivot" in text for role, text in captured
    )


@pytest.mark.asyncio
async def test_maybe_pivot_short_circuits_when_exhausted(monkeypatch):
    agent, _ = _make_orchestrator(monkeypatch)
    agent._adaptive_settings = AdaptiveSettings(
        enabled=True,
        rollout_mode=RolloutMode.ENFORCE,
        auto_pivot=True,
        max_pivots_per_run=1,
    )
    agent._repetition_handler = RepetitionHandler(max_pivots=1)
    first = await agent._maybe_pivot(
        "nmap_scan", {"target": "10.0.0.1"}, last_result="timeout"
    )
    second = await agent._maybe_pivot(
        "nmap_scan", {"target": "10.0.0.1"}, last_result="timeout"
    )
    assert first is not None
    assert second is None  # budget exhausted


@pytest.mark.asyncio
async def test_record_tactic_no_op_when_adaptive_off(monkeypatch):
    agent, _ = _make_orchestrator(monkeypatch)
    # Memory is None and adaptive_settings is None; must not raise.
    await agent._record_tactic("nmap_scan", {"target": "10.0.0.1"}, "ok")

