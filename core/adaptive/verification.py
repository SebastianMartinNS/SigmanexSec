"""
core/adaptive/verification.py — Verification & operator-feedback logic.

Pure functions used by the MCP ``verify_finding`` and ``operator_feedback``
tools. Keeping them isolated from I/O makes the rules trivially testable
and prevents drift between the MCP wrapper and the dashboard view.

The verification workflow is:

1. Build a *manifest* — a stable fingerprint of a finding's identity
   (host + category + title + cve + tool). It does **not** depend on
   the evidence text so that re-running the same check on a refreshed
   environment maps to the same manifest.
2. Apply an outcome (confirmed / drift / inconclusive) to compute a
   ``ConfidenceUpdate`` (new score, delta, rationale). Bonuses/penalties
   come from ``AdaptiveSettings`` so operators can tune behaviour from
   ``config.yaml`` without touching code.
3. Operator feedback is essentially a manual outcome with a stronger
   weight: ``confirm`` adds ``confirm_bonus``, ``refute`` subtracts
   ``drift_penalty``, ``note`` is a no-op on the score but is still
   audit-emitted so reviewers can see human input.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal, Optional

from core.adaptive.settings import AdaptiveSettings
from core.models import Finding


VerificationOutcome = Literal["confirmed", "drift", "inconclusive"]
FeedbackKind = Literal["confirm", "refute", "note"]


@dataclass(frozen=True)
class FindingManifest:
    """Stable fingerprint of a finding's identity."""
    finding_id: str
    digest: str  # short hex (16 chars) of host+category+title+cve+tool
    components: dict[str, str]


@dataclass(frozen=True)
class ConfidenceUpdate:
    """Result of applying a verification outcome to a finding."""
    previous: float
    new_value: float
    delta: float
    rationale: str
    drift: bool  # True if abs(delta) >= drift_threshold

    def to_dict(self) -> dict:
        return {
            "previous": round(self.previous, 4),
            "new_value": round(self.new_value, 4),
            "delta": round(self.delta, 4),
            "rationale": self.rationale,
            "drift": self.drift,
        }


def build_manifest(finding: Finding) -> FindingManifest:
    parts = {
        "host": str(finding.host_id or ""),
        "category": finding.category.value,
        "title": finding.title.strip().lower(),
        "cve": (finding.cve or "").strip().upper(),
        "tool": (finding.tool_used or "").strip().lower(),
    }
    blob = "|".join(f"{k}={v}" for k, v in parts.items())
    digest = hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]
    return FindingManifest(finding_id=finding.id, digest=digest, components=parts)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def apply_verification(
    *,
    finding: Finding,
    outcome: VerificationOutcome,
    settings: AdaptiveSettings,
    drift_threshold: float = 0.15,
) -> ConfidenceUpdate:
    """Compute the new confidence after a verification outcome.

    The deltas are taken from ``settings.confirm_bonus`` and
    ``settings.drift_penalty`` so they can be tuned via ``config.yaml``.
    """
    previous = float(finding.confidence)
    if outcome == "confirmed":
        delta = float(settings.confirm_bonus)
        rationale = "verification_confirmed (+confirm_bonus)"
    elif outcome == "drift":
        delta = -float(settings.drift_penalty)
        rationale = "verification_drift (-drift_penalty)"
    else:  # inconclusive
        delta = 0.0
        rationale = "verification_inconclusive (no score change)"

    new_value = _clamp(previous + delta)
    effective_delta = new_value - previous
    drift = abs(effective_delta) >= drift_threshold
    return ConfidenceUpdate(
        previous=previous,
        new_value=new_value,
        delta=effective_delta,
        rationale=rationale,
        drift=drift,
    )


def apply_operator_feedback(
    *,
    finding: Finding,
    kind: FeedbackKind,
    settings: AdaptiveSettings,
    operator: str = "operator",
    comment: Optional[str] = None,
) -> ConfidenceUpdate:
    """Map operator feedback to a ConfidenceUpdate.

    ``confirm`` and ``refute`` apply the same deltas as automatic
    verification; ``note`` is a zero-delta annotation. The rationale
    embeds the operator name so audit consumers can tell apart manual
    vs. automatic updates.
    """
    previous = float(finding.confidence)
    if kind == "confirm":
        delta = float(settings.confirm_bonus)
    elif kind == "refute":
        delta = -float(settings.drift_penalty)
    else:  # note
        delta = 0.0
    new_value = _clamp(previous + delta)
    effective_delta = new_value - previous
    suffix = f" :: {comment}" if comment else ""
    rationale = f"operator_feedback[{kind}] by {operator}{suffix}"
    drift = abs(effective_delta) >= 0.15
    return ConfidenceUpdate(
        previous=previous,
        new_value=new_value,
        delta=effective_delta,
        rationale=rationale,
        drift=drift,
    )
