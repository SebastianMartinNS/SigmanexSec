"""
core/adaptive/repetition.py — Anti-monotony runtime.

When the orchestrator's circuit-breaker detects the same (tool, args)
tuple invoked more times than ``SAP_TOOL_LOOP_LIMIT``, this module picks
a pivot suggestion instead of plain abort. The choice is deterministic:

1. If the active playbook defines a ``fallback_chain`` for the inferred
   failure class, the first symbolic option is surfaced.
2. Otherwise the static ``_FAMILY_PIVOTS`` table is consulted: for the
   failing tool we expose siblings from the same family (e.g. nmap →
   masscan / rustscan; sqli_test → command_injection_test).
3. As a last resort the suggestion is ``"diversify"``: the agent is
   asked to step back and re-plan.

Every pivot decision is also tracked so the orchestrator can refuse to
suggest the same alternative a second time inside one run (bounded by
``AdaptiveSettings.max_pivots_per_run``).

The handler is intentionally a small data class with pure functions: no
LLM calls, no async I/O. Audit emission and memory writes happen in the
orchestrator so this module stays trivially testable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from core.adaptive.playbook import Playbook


# Failure-class classifier (cheap regex over stderr/result text). Keep the
# token set small and stable — dashboards and KPI scripts depend on it.
_FAILURE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("timeout", re.compile(r"\b(time(d)?\s*out|deadline exceeded|signal 9)\b", re.I)),
    ("auth_failed", re.compile(r"\b(authentication failed|401|access denied|invalid (password|credentials))\b", re.I)),
    ("conn_refused", re.compile(r"\b(connection refused|no route to host|network unreachable)\b", re.I)),
    ("rate_limited", re.compile(r"\b(429|rate[- ]limit(ed)?|too many requests)\b", re.I)),
    ("permission_denied", re.compile(r"\b(permission denied|operation not permitted|EACCES)\b", re.I)),
    ("not_found", re.compile(r"\b(404|not found|no such file)\b", re.I)),
)


# Static fallback families used when no playbook is available. Ordered:
# the first sibling is the preferred pivot.
_FAMILY_PIVOTS: dict[str, tuple[str, ...]] = {
    "nmap_scan": ("masscan_scan", "rustscan", "netcat_probe"),
    "masscan_scan": ("nmap_scan", "rustscan"),
    "dir_fuzz": ("ffuf", "feroxbuster", "gobuster"),
    "web_fingerprint": ("whatweb", "wafw00f"),
    "web_vuln_scan": ("nuclei", "nikto"),
    "sqli_test": ("command_injection_test", "web_vuln_scan"),
    "brute_force": ("kerberoast", "asreproast", "credential_recheck"),
    "smb_enum": ("netexec_run", "enum4linux"),
    "netexec_run": ("smb_enum", "evil_winrm"),
    "kerberoast": ("asreproast", "secrets_dump"),
}


@dataclass(frozen=True)
class PivotSuggestion:
    """Outcome of a repetition event."""
    failure_class: str
    suggested_tool: Optional[str]
    fallback_kind: str  # "playbook" | "family" | "diversify"
    rationale: str

    def to_dict(self) -> dict:
        return {
            "failure_class": self.failure_class,
            "suggested_tool": self.suggested_tool,
            "fallback_kind": self.fallback_kind,
            "rationale": self.rationale,
        }


@dataclass
class RepetitionHandler:
    """Per-run, stateful pivot policy."""
    max_pivots: int = 3
    _used: set[str] = field(default_factory=set)
    _pivots_emitted: int = 0

    @property
    def remaining_pivots(self) -> int:
        return max(0, self.max_pivots - self._pivots_emitted)

    @staticmethod
    def classify_failure(text: str) -> str:
        if not text:
            return "unknown"
        for label, pat in _FAILURE_PATTERNS:
            if pat.search(text):
                return label
        return "unknown"

    def suggest(
        self,
        *,
        tool_name: str,
        last_result: str = "",
        playbook: Optional[Playbook] = None,
    ) -> PivotSuggestion:
        """Pick a pivot for ``tool_name`` after a repetition event.

        ``last_result`` is any short text that hints at why the tool failed
        (stderr, JSON ``{"error": ...}`` payload, etc.). It is only used
        for failure classification — never echoed back to the LLM.
        """
        failure_class = self.classify_failure(last_result)

        # 1) Playbook-driven fallback chain.
        if playbook is not None:
            chain = playbook.fallback_for(failure_class) or playbook.fallback_for("timeout")
            for option in chain:
                if option == "abort":
                    break
                if option in self._used:
                    continue
                self._used.add(option)
                self._pivots_emitted += 1
                return PivotSuggestion(
                    failure_class=failure_class,
                    suggested_tool=None if not _looks_like_tool(option) else option,
                    fallback_kind="playbook",
                    rationale=f"playbook.fallback_chain[{failure_class}] -> {option}",
                )

        # 2) Static family pivot.
        for sibling in _FAMILY_PIVOTS.get(tool_name, ()):
            if sibling in self._used:
                continue
            self._used.add(sibling)
            self._pivots_emitted += 1
            return PivotSuggestion(
                failure_class=failure_class,
                suggested_tool=sibling,
                fallback_kind="family",
                rationale=f"static family pivot for '{tool_name}' -> '{sibling}'",
            )

        # 3) Diversify directive.
        self._pivots_emitted += 1
        return PivotSuggestion(
            failure_class=failure_class,
            suggested_tool=None,
            fallback_kind="diversify",
            rationale="no fallback available; agent must step back and re-plan",
        )

    def is_exhausted(self) -> bool:
        return self._pivots_emitted >= self.max_pivots


def _looks_like_tool(option: str) -> bool:
    """Heuristic: playbook fallback options can be tool names or directives.

    Tool names typically contain an underscore or a dash and don't match
    one of the well-known directive tokens.
    """
    directives = {
        "abort", "narrow_scope", "scope_recheck", "credential_recheck",
        "alt_tool_suggestion", "backoff", "diversify",
    }
    if option in directives:
        return False
    return bool(re.match(r"^[a-z][a-z0-9_\-]*$", option))


def format_tactic_entry(*, status: str, tool: str, target: str, outcome: str) -> str:
    """Render a single line for the tactics_log core block.

    Format: ``[status] tool target -> outcome`` truncated at 200 chars so
    the block stays under its 2.5KB cap even after dozens of entries.
    """
    status = status.lower().strip() or "ok"
    if status not in {"ok", "fail", "pivot", "skip"}:
        status = "ok"
    tool = (tool or "?")[:32]
    target = (target or "-")[:48]
    outcome = re.sub(r"\s+", " ", outcome or "").strip()[:120]
    return f"[{status}] {tool} {target} -> {outcome}"


def derive_tactic_status(result_text: str) -> str:
    """Map a tool result string to a tactic status label.

    The orchestrator already wraps aborted/skipped/plan-only outcomes in
    JSON envelopes, so we can detect them cheaply without parsing.
    """
    if not result_text:
        return "ok"
    snippet = result_text[:512]
    if '"aborted": true' in snippet or "aborted" in snippet.lower() and "circuit-breaker" in snippet.lower():
        return "pivot"
    if '"skipped": true' in snippet or '"plan_only": true' in snippet:
        return "skip"
    if '"error"' in snippet or "Error" in snippet or "failed" in snippet.lower():
        return "fail"
    return "ok"
