"""
core/adaptive/confidence.py — Evidence-based confidence scoring.

A small, deterministic heuristic that maps tool execution outcomes (and
optional finding context) to a numeric score in [0.0, 1.0]. The goal is
to surface "how well grounded is this claim?" without a second LLM call.

Design notes:
- Heuristic only; no model inference here. The score is meant as a
  ranking/priority signal for the orchestrator, the dashboard and the
  reporting layer, not as a hard truth.
- The function is pure: same inputs -> same score + rationale. This makes
  it cheap to unit-test and audit.
- Penalties dominate over bonuses to bias the system toward caution.

Scoring rubric (v1):
    base                                    = 0.50
    + tool exited cleanly (rc == 0)         + 0.10
    + stdout non-empty                      + 0.05
    + matches at least one expected pattern + 0.15
    + matches >= 2 expected patterns        + 0.05
    + CVE id present in finding             + 0.10
    + multi-tool corroboration (>=2 tools)  + 0.10
    + operator approved evidence            + 0.05
    - tool timed out (rc == 124)            - 0.30
    - non-zero rc (other than timeout)      - 0.15
    - stderr contains "warning|error" tokens- 0.05
    - output truncated                      - 0.05
    - no evidence_audit_ids attached        - 0.10

Score is clamped to [0.0, 1.0]. The rationale string lists every rule
that contributed so the operator can audit why a finding looks weak.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from core.models import ExecutionResult, Finding

# --------------------------------------------------------------------------- #
# Public types                                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ConfidenceScore:
    value: float
    rationale: str
    contributors: tuple[tuple[str, float], ...] = field(default_factory=tuple)

    def clamped(self) -> ConfidenceScore:
        v = max(0.0, min(1.0, self.value))
        if v == self.value:
            return self
        return ConfidenceScore(v, self.rationale, self.contributors)


# --------------------------------------------------------------------------- #
# Scoring                                                                     #
# --------------------------------------------------------------------------- #


_BASE = 0.50
_STDERR_NOISE_RE = re.compile(r"\b(warning|error|failed|fatal)\b", re.IGNORECASE)


def score_from_execution(
    result: ExecutionResult | None,
    *,
    expected_patterns: Sequence[str] = (),
    corroborating_tools: Sequence[str] = (),
    operator_approved: bool = False,
    cve: str = "",
    has_evidence_links: bool = False,
) -> ConfidenceScore:
    """Score a single tool execution outcome.

    Parameters
    ----------
    result:
        The ExecutionResult. ``None`` is treated as "no evidence" -> base/2.
    expected_patterns:
        Regex patterns expected in stdout (case-insensitive).
    corroborating_tools:
        Names of *other* tools that confirmed the same observation.
    operator_approved:
        Whether a human operator explicitly approved the evidence.
    cve:
        CVE identifier, if any, attached to the eventual finding.
    has_evidence_links:
        True iff the finding (or upcoming finding) has audit-id provenance.
    """
    contributors: list[tuple[str, float]] = [("base", _BASE)]
    score = _BASE

    if result is None:
        contributors.append(("no_execution_result", -_BASE / 2))
        score -= _BASE / 2
        return ConfidenceScore(
            max(0.0, min(1.0, score)),
            "; ".join(f"{k}{v:+.2f}" for k, v in contributors),
            tuple(contributors),
        ).clamped()

    rc = result.returncode
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    if rc == 0:
        contributors.append(("returncode_ok", +0.10))
        score += 0.10
    elif rc == 124:
        contributors.append(("timeout", -0.30))
        score -= 0.30
    else:
        contributors.append(("returncode_nonzero", -0.15))
        score -= 0.15

    if stdout.strip():
        contributors.append(("stdout_present", +0.05))
        score += 0.05

    if expected_patterns:
        matches = sum(
            1 for p in expected_patterns
            if p and re.search(p, stdout, re.IGNORECASE)
        )
        if matches >= 1:
            contributors.append(("expected_pattern_match", +0.15))
            score += 0.15
        if matches >= 2:
            contributors.append(("multi_pattern_match", +0.05))
            score += 0.05

    if cve:
        contributors.append(("cve_present", +0.10))
        score += 0.10

    if len(corroborating_tools) >= 2:
        contributors.append(("multi_tool_corroboration", +0.10))
        score += 0.10

    if operator_approved:
        contributors.append(("operator_approved", +0.05))
        score += 0.05

    if stderr and _STDERR_NOISE_RE.search(stderr):
        contributors.append(("stderr_noise", -0.05))
        score -= 0.05

    if result.truncated:
        contributors.append(("output_truncated", -0.05))
        score -= 0.05

    if not has_evidence_links:
        contributors.append(("no_evidence_links", -0.10))
        score -= 0.10

    rationale = "; ".join(f"{k}{v:+.2f}" for k, v in contributors)
    return ConfidenceScore(score, rationale, tuple(contributors)).clamped()


def score_finding(
    finding: Finding,
    *,
    last_result: ExecutionResult | None = None,
    expected_patterns: Sequence[str] = (),
    corroborating_tools: Sequence[str] = (),
    operator_approved: bool = False,
) -> ConfidenceScore:
    """Score a finding using its embedded provenance plus optional context."""
    return score_from_execution(
        last_result,
        expected_patterns=expected_patterns,
        corroborating_tools=corroborating_tools,
        operator_approved=operator_approved,
        cve=finding.cve,
        has_evidence_links=bool(finding.evidence_audit_ids),
    )
