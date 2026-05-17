"""Unit tests for core/adaptive/confidence.py."""
from __future__ import annotations

import pytest

from core.adaptive.confidence import score_finding, score_from_execution
from core.models import (
    ExecutionResult,
    Finding,
    FindingCategory,
    Phase,
    Severity,
)


def _result(rc: int = 0, stdout: str = "", stderr: str = "", truncated: bool = False) -> ExecutionResult:
    return ExecutionResult(
        tool="nmap",
        command="nmap -sV 10.0.0.5",
        stdout=stdout,
        stderr=stderr,
        returncode=rc,
        duration_seconds=1.0,
        truncated=truncated,
        engagement_id="eng-1",
        phase=Phase.SCANNING,
    )


def _finding(**kwargs) -> Finding:
    base = dict(
        engagement_id="eng-1",
        severity=Severity.MEDIUM,
        category=FindingCategory.OPEN_PORT,
        title="t",
        description="d",
    )
    base.update(kwargs)
    return Finding(**base)


def test_score_no_execution_result_yields_low_score():
    s = score_from_execution(None)
    assert 0.0 <= s.value <= 0.5
    assert "no_execution_result" in s.rationale


def test_score_clean_run_with_pattern_match_increases():
    s = score_from_execution(
        _result(rc=0, stdout="22/tcp open ssh OpenSSH 8.2"),
        expected_patterns=[r"22/tcp\s+open"],
        has_evidence_links=True,
    )
    # base 0.5 + rc_ok 0.10 + stdout 0.05 + pattern 0.15 = 0.80
    assert s.value == pytest.approx(0.80, abs=1e-6)
    assert "expected_pattern_match" in s.rationale


def test_score_timeout_dominates():
    s = score_from_execution(_result(rc=124, stdout=""), has_evidence_links=True)
    # base 0.5 - timeout 0.30 = 0.20 (no other contributors)
    assert s.value == pytest.approx(0.20, abs=1e-6)


def test_score_clamped_to_unit_interval():
    s = score_from_execution(
        _result(rc=0, stdout="cve-2024-1234 22/tcp open ssh banner"),
        expected_patterns=[r"22/tcp", r"ssh", r"banner"],
        corroborating_tools=["masscan", "rustscan"],
        operator_approved=True,
        cve="CVE-2024-1234",
        has_evidence_links=True,
    )
    assert s.value <= 1.0
    assert s.value >= 0.95


def test_score_finding_uses_provenance_links():
    f_no_links = _finding()
    f_with_links = _finding(evidence_audit_ids=["a1", "a2"], cve="CVE-2024-9")
    r = _result(rc=0, stdout="banner")

    s_no = score_finding(f_no_links, last_result=r)
    s_yes = score_finding(f_with_links, last_result=r)
    assert s_yes.value > s_no.value


def test_decision_kind_namespace_is_stable():
    from core.adaptive.decisions import DecisionKind
    # Closed enum used by dashboard/KPI scripts.
    assert DecisionKind.REPETITION_BLOCKED.value == "decision.repetition_blocked"
    assert DecisionKind.SCENARIO_CLASSIFIED.value == "decision.scenario_classified"
