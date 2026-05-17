"""
core/adaptive/playbook.py — Declarative playbook router.

Loads YAML templates from ``playbooks/<scenario>.yaml`` and exposes a small,
stateless API the orchestrator calls during a run to:

1. Pick the tactical step set for the *current phase* of the engagement.
2. Resolve a *fallback chain* when a tool execution fails (timeout,
   auth_failed, conn_refused, ...).
3. Track which playbook branches have already been visited (to avoid
   getting stuck in a loop — see Phase 4 anti-monotony work).

Templates are intentionally simple YAML so red-team operators can edit
them without touching Python code. The router treats unknown fields as
forward-compatibility metadata and ignores them.

Schema (informal):

    scenario: web
    description: "Web application playbook"
    fallback_chain:
      timeout: ["alt_tool_suggestion", "narrow_scope", "abort"]
      auth_failed: ["credential_recheck", "alt_tool_suggestion"]
      conn_refused: ["scope_recheck", "alt_tool_suggestion"]
    phases:
      reconnaissance:
        - tool: web_fingerprint
          rationale: "Detect framework / CMS to pick a deeper scan."
          stop_when:
            - "framework_identified"
        - tool: dir_fuzz
          rationale: "Discover hidden endpoints."
      scanning:
        - tool: web_vuln_scan
          rationale: "Run automated vuln check."
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Resolved at import time so the router never hits the filesystem outside this dir.
_PLAYBOOK_DIR = Path(__file__).resolve().parents[2] / "playbooks"


# --------------------------------------------------------------------------- #
# Data model                                                                  #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PlaybookStep:
    tool: str
    rationale: str = ""
    stop_when: tuple[str, ...] = field(default_factory=tuple)
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "rationale": self.rationale,
            "stop_when": list(self.stop_when),
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True)
class Playbook:
    scenario: str
    description: str
    phases: dict[str, tuple[PlaybookStep, ...]]
    fallback_chain: dict[str, tuple[str, ...]]

    def steps_for_phase(self, phase: str) -> tuple[PlaybookStep, ...]:
        # `Phase` enum values use the long names ("reconnaissance"...).
        return self.phases.get(phase, ()) or self.phases.get(phase.lower(), ())

    def fallback_for(self, failure_class: str) -> tuple[str, ...]:
        return self.fallback_chain.get(failure_class, ())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "description": self.description,
            "phases": {
                k: [s.to_dict() for s in v] for k, v in self.phases.items()
            },
            "fallback_chain": {k: list(v) for k, v in self.fallback_chain.items()},
        }


# --------------------------------------------------------------------------- #
# Router                                                                      #
# --------------------------------------------------------------------------- #


class PlaybookNotFound(LookupError):
    """Raised by the router when no template exists for a scenario."""


class PlaybookRouter:
    """Loads + caches playbook YAML files."""

    _CACHE: dict[str, Playbook] = {}

    @classmethod
    def reset_cache(cls) -> None:
        cls._CACHE.clear()

    @classmethod
    def list_scenarios(cls, base_dir: Path | None = None) -> list[str]:
        d = base_dir or _PLAYBOOK_DIR
        if not d.is_dir():
            return []
        return sorted(p.stem for p in d.glob("*.yaml"))

    @classmethod
    def load(cls, scenario: str, *, base_dir: Path | None = None) -> Playbook:
        cache_key = f"{base_dir or _PLAYBOOK_DIR}::{scenario}"
        if cache_key in cls._CACHE:
            return cls._CACHE[cache_key]
        d = base_dir or _PLAYBOOK_DIR
        path = d / f"{scenario}.yaml"
        if not path.exists():
            raise PlaybookNotFound(f"no playbook for scenario={scenario!r} at {path}")
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PlaybookNotFound(f"invalid YAML in {path}: {exc}") from exc

        pb = cls._build(data, fallback_scenario=scenario)
        cls._CACHE[cache_key] = pb
        return pb

    @classmethod
    def load_or_none(cls, scenario: str, *, base_dir: Path | None = None) -> Playbook | None:
        try:
            return cls.load(scenario, base_dir=base_dir)
        except PlaybookNotFound:
            return None

    @staticmethod
    def _build(data: dict, *, fallback_scenario: str) -> Playbook:
        phases_raw = data.get("phases") or {}
        phases: dict[str, tuple[PlaybookStep, ...]] = {}
        for phase_name, steps in phases_raw.items():
            built: list[PlaybookStep] = []
            for entry in steps or []:
                if not isinstance(entry, dict) or "tool" not in entry:
                    continue
                stop_when = entry.get("stop_when") or []
                if not isinstance(stop_when, (list, tuple)):
                    stop_when = [str(stop_when)]
                params = entry.get("parameters") or {}
                if not isinstance(params, dict):
                    params = {}
                built.append(PlaybookStep(
                    tool=str(entry["tool"]),
                    rationale=str(entry.get("rationale", "")),
                    stop_when=tuple(str(x) for x in stop_when),
                    parameters=params,
                ))
            phases[str(phase_name)] = tuple(built)

        fallback_raw = data.get("fallback_chain") or {}
        fallback: dict[str, tuple[str, ...]] = {}
        for failure_class, options in fallback_raw.items():
            if not isinstance(options, (list, tuple)):
                continue
            fallback[str(failure_class)] = tuple(str(x) for x in options)

        return Playbook(
            scenario=str(data.get("scenario") or fallback_scenario),
            description=str(data.get("description", "")),
            phases=phases,
            fallback_chain=fallback,
        )


def render_advisory(playbook: Playbook, phase: str, *, max_steps: int = 5) -> str:
    """Render a compact advisory block for the agent context.

    The output is plain text (no YAML/JSON) so the model can parse it
    quickly and the dashboard can show it verbatim. Designed to fit in
    < 800 tokens for the typical playbook.
    """
    steps = playbook.steps_for_phase(phase)[:max_steps]
    lines = [
        f"# Tactical playbook: {playbook.scenario} (phase={phase})",
        playbook.description.strip() or "(no description)",
        "",
        "Suggested next steps (advisory only — adapt to live evidence):",
    ]
    if not steps:
        lines.append("  (no steps defined for this phase; rely on PTES heuristics)")
    for i, step in enumerate(steps, 1):
        lines.append(f"  {i}. {step.tool} — {step.rationale or 'no rationale'}")
        if step.stop_when:
            lines.append(f"     stop_when: {', '.join(step.stop_when)}")
    if playbook.fallback_chain:
        lines.append("")
        lines.append("Fallback chain (on tool failure):")
        for cls, opts in playbook.fallback_chain.items():
            lines.append(f"  - {cls}: {' -> '.join(opts)}")
    return "\n".join(lines).strip()
