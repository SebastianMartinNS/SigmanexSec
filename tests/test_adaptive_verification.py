"""Tests for the Phase-5 verification & operator-feedback layer."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from core.adaptive import (
    AdaptiveSettings,
    ConfidenceUpdate,
    FindingManifest,
    RolloutMode,
    apply_operator_feedback,
    apply_verification,
    build_manifest,
)
from core.adaptive.verification import _clamp
from core.models import Finding, FindingCategory, Severity
from core.session_store import SessionStore
from core.time_utils import utcnow as _sap_utcnow


def _make_finding(**overrides) -> Finding:
    base = dict(
        engagement_id="eng-1",
        host_id="h-1",
        severity=Severity.HIGH,
        category=FindingCategory.SQLI,
        title="Boolean-Based Blind SQLi",
        description="param id is injectable",
        evidence="rows differ on 1=1 vs 1=2",
        cve="CVE-2023-12345",
        tool_used="sqli_test",
        confidence=0.60,
        confidence_rationale="initial detection",
    )
    base.update(overrides)
    return Finding(**base)


def _settings(*, confirm_bonus=0.10, drift_penalty=0.20) -> AdaptiveSettings:
    return AdaptiveSettings(
        enabled=True,
        rollout_mode=RolloutMode.ENFORCE,
        confirm_bonus=confirm_bonus,
        drift_penalty=drift_penalty,
    )


# ── manifest ─────────────────────────────────────────────────────────────────


def test_manifest_is_stable_across_evidence_changes():
    a = _make_finding(evidence="payload v1")
    b = _make_finding(evidence="payload v2 (different text)")
    ma, mb = build_manifest(a), build_manifest(b)
    assert isinstance(ma, FindingManifest)
    assert ma.digest == mb.digest
    assert ma.components["cve"] == "CVE-2023-12345"


def test_manifest_changes_when_identity_changes():
    a = _make_finding()
    b = _make_finding(title="completely different finding")
    assert build_manifest(a).digest != build_manifest(b).digest


# ── apply_verification ───────────────────────────────────────────────────────


def test_verification_confirmed_bumps_confidence():
    f = _make_finding(confidence=0.55)
    upd = apply_verification(finding=f, outcome="confirmed", settings=_settings())
    assert isinstance(upd, ConfidenceUpdate)
    assert upd.previous == pytest.approx(0.55)
    assert upd.new_value == pytest.approx(0.65)
    assert upd.delta == pytest.approx(0.10)
    assert upd.drift is False


def test_verification_drift_lowers_confidence_and_flags_drift():
    f = _make_finding(confidence=0.80)
    upd = apply_verification(finding=f, outcome="drift", settings=_settings())
    assert upd.new_value == pytest.approx(0.60)
    assert upd.delta == pytest.approx(-0.20)
    assert upd.drift is True


def test_verification_inconclusive_is_zero_delta():
    f = _make_finding(confidence=0.40)
    upd = apply_verification(finding=f, outcome="inconclusive", settings=_settings())
    assert upd.new_value == pytest.approx(0.40)
    assert upd.delta == pytest.approx(0.0)
    assert upd.drift is False


def test_verification_clamps_to_unit_interval():
    high = _make_finding(confidence=0.95)
    upd_high = apply_verification(finding=high, outcome="confirmed", settings=_settings())
    assert upd_high.new_value <= 1.0
    low = _make_finding(confidence=0.05)
    upd_low = apply_verification(finding=low, outcome="drift", settings=_settings())
    assert upd_low.new_value >= 0.0


def test_verification_drift_threshold_respected():
    f = _make_finding(confidence=0.50)
    upd = apply_verification(
        finding=f, outcome="drift", settings=_settings(drift_penalty=0.10),
        drift_threshold=0.15,
    )
    # delta is -0.10, below threshold => not flagged as drift.
    assert upd.delta == pytest.approx(-0.10)
    assert upd.drift is False


# ── apply_operator_feedback ──────────────────────────────────────────────────


def test_operator_confirm_adds_bonus():
    f = _make_finding(confidence=0.50)
    upd = apply_operator_feedback(
        finding=f, kind="confirm", settings=_settings(), operator="alice",
    )
    assert upd.delta == pytest.approx(0.10)
    assert "operator_feedback[confirm]" in upd.rationale
    assert "alice" in upd.rationale


def test_operator_refute_subtracts_penalty():
    f = _make_finding(confidence=0.70)
    upd = apply_operator_feedback(
        finding=f, kind="refute", settings=_settings(), operator="bob",
    )
    assert upd.new_value == pytest.approx(0.50)
    assert upd.drift is True


def test_operator_note_is_zero_delta_with_comment():
    f = _make_finding(confidence=0.50)
    upd = apply_operator_feedback(
        finding=f, kind="note", settings=_settings(),
        operator="reviewer", comment="needs context",
    )
    assert upd.delta == pytest.approx(0.0)
    assert "needs context" in upd.rationale


# ── SessionStore.update_finding_confidence ───────────────────────────────────


@pytest.mark.asyncio
async def test_update_finding_confidence_persists_and_increments(tmp_path):
    db = tmp_path / "assessments.db"
    store = SessionStore(str(db))
    await store.init()
    f = _make_finding(confidence=0.50)
    await store.add_finding(f)

    new_ts = _sap_utcnow() + timedelta(seconds=1)
    ok = await store.update_finding_confidence(
        f.id,
        new_confidence=0.65,
        rationale="verification_confirmed",
        freshness_ts=new_ts,
        increment_verification=True,
    )
    assert ok is True
    refreshed = await store.get_finding(f.id)
    assert refreshed is not None
    assert refreshed.confidence == pytest.approx(0.65)
    assert refreshed.confidence_rationale == "verification_confirmed"
    assert refreshed.verification_count == 1


@pytest.mark.asyncio
async def test_update_finding_confidence_resets_counter_on_drift(tmp_path):
    db = tmp_path / "assessments.db"
    store = SessionStore(str(db))
    await store.init()
    f = _make_finding(confidence=0.80, verification_count=3)
    await store.add_finding(f)

    await store.update_finding_confidence(
        f.id,
        new_confidence=0.55,
        rationale="verification_drift",
        freshness_ts=_sap_utcnow(),
        reset_verification=True,
    )
    refreshed = await store.get_finding(f.id)
    assert refreshed is not None
    assert refreshed.verification_count == 0


@pytest.mark.asyncio
async def test_update_finding_confidence_returns_false_for_unknown_id(tmp_path):
    db = tmp_path / "assessments.db"
    store = SessionStore(str(db))
    await store.init()
    ok = await store.update_finding_confidence(
        "nope-no-such-id",
        new_confidence=0.5,
        rationale="x",
        freshness_ts=_sap_utcnow(),
    )
    assert ok is False


def test_clamp_helper():
    assert _clamp(-0.2) == 0.0
    assert _clamp(1.4) == 1.0
    assert _clamp(0.42) == pytest.approx(0.42)
