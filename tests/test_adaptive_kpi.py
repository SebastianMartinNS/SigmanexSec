"""Tests for the Phase-6 KPI / quality-gate computation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.adaptive import (
    DecisionKind,
    KPIReport,
    compute_kpi_from_path,
    compute_kpi_report,
    iter_audit_rows,
)
from core.models import Finding, FindingCategory, Severity


def _f(**overrides) -> Finding:
    base = dict(
        engagement_id="eng-1",
        severity=Severity.MEDIUM,
        category=FindingCategory.OTHER,
        title="t",
        description="d",
    )
    base.update(overrides)
    return Finding(**base)


# ── Pure function ────────────────────────────────────────────────────────────


def test_empty_inputs_produce_zero_report():
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=[], findings=[])
    assert isinstance(rep, KPIReport)
    assert rep.total_tool_calls == 0
    assert rep.tool_repetition_rate == 0.0
    assert rep.pivot_rate == 0.0
    assert rep.hallucination_proxy == 0
    assert rep.confidence_distribution == {"low": 0, "medium": 0, "high": 0}


def test_repetition_and_pivot_rates():
    rows = [
        {"engagement_id": "eng-1", "action": "tool_executed"},
        {"engagement_id": "eng-1", "action": "tool_executed"},
        {"engagement_id": "eng-1", "action": "tool_executed"},
        {"engagement_id": "eng-1", "action": "tool_executed"},
        {"engagement_id": "eng-1", "action": DecisionKind.REPETITION_BLOCKED.value},
        {"engagement_id": "eng-1", "action": DecisionKind.REPETITION_PIVOT.value},
    ]
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=rows, findings=[])
    assert rep.total_tool_calls == 4
    assert rep.repetition_blocked == 1
    assert rep.repetition_pivots == 1
    assert rep.tool_repetition_rate == pytest.approx(0.25)
    assert rep.pivot_rate == pytest.approx(1.0)


def test_other_engagement_rows_are_ignored():
    rows = [
        {"engagement_id": "eng-1", "action": "tool_executed"},
        {"engagement_id": "eng-2", "action": "tool_executed"},  # noise
        {"engagement_id": "eng-2", "action": DecisionKind.REPETITION_BLOCKED.value},
    ]
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=rows, findings=[])
    assert rep.total_tool_calls == 1
    assert rep.repetition_blocked == 0


def test_hallucination_proxy_only_flags_high_conf_without_evidence():
    findings = [
        _f(confidence=0.85, evidence_audit_ids=[]),         # flagged
        _f(confidence=0.85, evidence_audit_ids=["a-1"]),    # OK
        _f(confidence=0.50, evidence_audit_ids=[]),         # not high conf
        _f(confidence=0.95, evidence_audit_ids=[]),         # flagged
    ]
    rep = compute_kpi_report(
        engagement_id="eng-1", audit_rows=[], findings=findings,
    )
    assert rep.hallucination_proxy == 2
    assert rep.findings_total == 4


def test_confidence_distribution_buckets():
    findings = [
        _f(confidence=0.10),
        _f(confidence=0.39),
        _f(confidence=0.40),
        _f(confidence=0.69),
        _f(confidence=0.70),
        _f(confidence=1.00),
    ]
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=[], findings=findings)
    assert rep.confidence_distribution == {"low": 2, "medium": 2, "high": 2}


def test_drift_rate_separates_drift_from_plain_updates():
    rows = [
        {"engagement_id": "eng-1", "action": DecisionKind.CONFIDENCE_UPDATED.value},
        {"engagement_id": "eng-1", "action": DecisionKind.CONFIDENCE_UPDATED.value},
        {"engagement_id": "eng-1", "action": DecisionKind.DRIFT_DETECTED.value},
    ]
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=rows, findings=[])
    assert rep.verifications == 3
    assert rep.drift_events == 1
    assert rep.drift_rate == pytest.approx(1 / 3)


def test_decision_counts_seeded_with_all_kinds():
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=[], findings=[])
    # All known DecisionKind values are pre-seeded with 0 so the dashboard
    # chart never has to handle missing keys.
    expected_keys = {k.value for k in DecisionKind}
    assert expected_keys.issubset(set(rep.decision_counts.keys()))
    assert all(v == 0 for v in rep.decision_counts.values())


def test_unknown_decision_kind_is_recorded_safely():
    rows = [{"engagement_id": "eng-1", "action": "decision.future_kind"}]
    rep = compute_kpi_report(engagement_id="eng-1", audit_rows=rows, findings=[])
    # Forward-compat: unseen decision strings still appear in the histogram.
    assert rep.decision_counts.get("decision.future_kind") == 1


# ── End-to-end: audit JSONL → KPI ────────────────────────────────────────────


def test_compute_kpi_from_path_reads_jsonl(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    rows = [
        {"engagement_id": "eng-X", "action": "tool_executed"},
        {"engagement_id": "eng-X", "action": "tool_executed"},
        {"engagement_id": "eng-X", "action": DecisionKind.REPETITION_BLOCKED.value},
        {"engagement_id": "eng-Y", "action": "tool_executed"},  # noise
    ]
    audit.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    findings = [_f(confidence=0.9, evidence_audit_ids=[])]

    rep = compute_kpi_from_path(
        engagement_id="eng-X", audit_path=audit, findings=findings,
    )
    assert rep.total_tool_calls == 2
    assert rep.repetition_blocked == 1
    assert rep.tool_repetition_rate == pytest.approx(0.5)
    assert rep.hallucination_proxy == 1


def test_iter_audit_rows_skips_invalid_lines(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        '{"engagement_id":"eng-1","action":"tool_executed"}\n'
        "this is not json\n"
        "\n"
        '{"engagement_id":"eng-1","action":"tool_executed"}\n'
    )
    rows = list(iter_audit_rows(audit, engagement_id="eng-1"))
    assert len(rows) == 2
    assert all(r["action"] == "tool_executed" for r in rows)


def test_iter_audit_rows_returns_empty_on_missing_path(tmp_path: Path):
    audit = tmp_path / "does_not_exist.jsonl"
    assert list(iter_audit_rows(audit, engagement_id="eng-1")) == []
