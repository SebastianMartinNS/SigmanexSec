"""Phase 5: orchestrator smart truncation."""
from __future__ import annotations

from agent.orchestrator import Orchestrator, _CALLBACK_RESULT_CAP


def test_truncate_under_cap_unchanged():
    text = "hello world"
    assert Orchestrator._truncate_for_callback(text) == text


def test_truncate_none_returns_empty():
    assert Orchestrator._truncate_for_callback(None) == ""  # type: ignore[arg-type]


def test_truncate_over_cap_keeps_head_and_tail():
    body = "X" * (_CALLBACK_RESULT_CAP * 2)
    out = Orchestrator._truncate_for_callback(body)
    assert "[truncated" in out
    # tail must be preserved (last char of original is X-block end)
    assert out.startswith("X" * 100)
    assert out.endswith("X" * 100)
    # length should be roughly the cap + marker overhead
    assert len(out) <= _CALLBACK_RESULT_CAP + 200


def test_truncate_extracts_output_ref_uri():
    body = (
        "A" * (_CALLBACK_RESULT_CAP)
        + ' ... "stdout_uri": "sap://run/r1/output/call_abc/stdout" ...'
        + "B" * 100
    )
    out = Orchestrator._truncate_for_callback(body)
    assert "sap://run/r1/output/call_abc/stdout" in out


def test_summarize_result_short_unchanged():
    assert Orchestrator._summarize_result_for_tactic("brief") == "brief"


def test_summarize_result_long_head_tail():
    s = ("HEAD" * 50) + ("MIDDLE" * 100) + ("TAIL" * 50)
    out = Orchestrator._summarize_result_for_tactic(s)
    assert " … " in out
    assert out.startswith("HEAD")
    assert out.endswith("TAIL")
    assert len(out) <= 220
