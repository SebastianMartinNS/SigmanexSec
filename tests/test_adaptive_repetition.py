"""Tests for the Phase-4 anti-monotony layer (RepetitionHandler + helpers)."""
from __future__ import annotations

import pytest

from core.adaptive import (
    PivotSuggestion,
    PlaybookRouter,
    RepetitionHandler,
    derive_tactic_status,
    format_tactic_entry,
)


@pytest.fixture(autouse=True)
def _reset_playbook_cache():
    PlaybookRouter.reset_cache()
    yield
    PlaybookRouter.reset_cache()


# ── classify_failure ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, expected",
    [
        ("connection timed out after 30s", "timeout"),
        ("Authentication failed: invalid credentials", "auth_failed"),
        ("connection refused on tcp/443", "conn_refused"),
        ("HTTP 429 too many requests", "rate_limited"),
        ("permission denied while writing", "permission_denied"),
        ("HTTP 404 not found", "not_found"),
        ("clean output without any error", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_failure(text, expected):
    assert RepetitionHandler.classify_failure(text) == expected


# ── suggest() ────────────────────────────────────────────────────────────────


def test_suggest_uses_static_family_when_no_playbook():
    h = RepetitionHandler(max_pivots=3)
    s = h.suggest(tool_name="nmap_scan", last_result="connection timed out")
    assert isinstance(s, PivotSuggestion)
    assert s.fallback_kind == "family"
    assert s.suggested_tool == "masscan_scan"
    assert s.failure_class == "timeout"
    assert h.remaining_pivots == 2


def test_suggest_avoids_repeating_same_pivot():
    h = RepetitionHandler(max_pivots=5)
    first = h.suggest(tool_name="nmap_scan", last_result="timeout")
    second = h.suggest(tool_name="nmap_scan", last_result="timeout")
    assert first.suggested_tool == "masscan_scan"
    assert second.suggested_tool != first.suggested_tool
    # next preferred sibling per _FAMILY_PIVOTS table
    assert second.suggested_tool in {"rustscan", "netcat_probe"}


def test_suggest_returns_diversify_when_no_match():
    h = RepetitionHandler(max_pivots=3)
    s = h.suggest(tool_name="completely_unknown_tool", last_result="boom")
    assert s.fallback_kind == "diversify"
    assert s.suggested_tool is None


def test_suggest_uses_playbook_fallback_chain():
    pb = PlaybookRouter.load("web")
    h = RepetitionHandler(max_pivots=3)
    s = h.suggest(
        tool_name="web_vuln_scan",
        last_result="connection timed out",
        playbook=pb,
    )
    assert s.fallback_kind == "playbook"
    assert s.failure_class == "timeout"
    # The advisory must surface the chain entry, not a static sibling.
    assert "fallback_chain[timeout]" in s.rationale


def test_max_pivots_is_respected():
    h = RepetitionHandler(max_pivots=2)
    h.suggest(tool_name="nmap_scan", last_result="timeout")
    h.suggest(tool_name="nmap_scan", last_result="timeout")
    assert h.is_exhausted()
    assert h.remaining_pivots == 0


# ── tactics_log helpers ──────────────────────────────────────────────────────


def test_format_tactic_entry_truncates_and_normalizes():
    line = format_tactic_entry(
        status="OK",
        tool="nmap_scan",
        target="10.0.0.1",
        outcome="ports\nopen:  22, 80,\t443",
    )
    assert line.startswith("[ok] nmap_scan 10.0.0.1 -> ")
    assert "\n" not in line
    assert "\t" not in line


def test_format_tactic_entry_clamps_status_label():
    line = format_tactic_entry(
        status="weird-status",
        tool="t", target="x", outcome="o",
    )
    # Unknown status falls back to "ok".
    assert line.startswith("[ok] ")


@pytest.mark.parametrize(
    "result, expected",
    [
        ('{"aborted": true, "reason": "x"}', "pivot"),
        ('{"skipped": true}', "skip"),
        ('{"plan_only": true}', "skip"),
        ('{"error": "boom"}', "fail"),
        ("ports open: 22,80,443", "ok"),
        ("", "ok"),
    ],
)
def test_derive_tactic_status(result, expected):
    assert derive_tactic_status(result) == expected
