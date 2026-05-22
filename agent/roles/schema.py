"""
agent/roles/schema.py — Pydantic models for a multi-agent role.

A ``Role`` is a static description of what one specialist agent is
allowed to do. The fields are deliberately small so a YAML file fits on
one screen — the community contribution guide in
``docs/CONTRIBUTING_ROLES.md`` walks through an example.

Authority for runtime enforcement lives in
:mod:`core.role_validator` (Milestone C2), which composes on top of the
existing ``scope_validator`` chokepoint without duplicating it.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models import Phase


class RoleCapabilityGuard(BaseModel):
    """Per-role runtime safety knobs.

    These are *advisory* hints for the orchestrator — the chokepoint
    (``ToolExecutor.run_request``) does not implement them directly; the
    Coordinator and AgenticLoop consult them when scheduling work.
    """

    model_config = ConfigDict(frozen=True)

    requires_phase: list[Phase] = Field(default_factory=list)
    """When non-empty, the role refuses to act outside these PTES phases."""

    requires_human_approval: bool = False
    """Step-mode equivalent at the role granularity.

    When True, every tool call by this role goes through the approval
    gate even if the orchestrator-wide mode is EXECUTION. Used for
    high-stakes roles like ExploitDev.
    """

    max_tool_calls_per_step: int = 5
    """Upper bound on the tool calls a single iteration of this role may
    request. Above this the loop forces a reflection or handoff."""


class RoleHandoff(BaseModel):
    """One outgoing handoff edge with a human-readable when-to-use hint."""

    model_config = ConfigDict(frozen=True)

    to: str
    """Target ``role.id``. Validated at registry load time."""

    when: str = ""
    """Hint surfaced to the Coordinator (and to the role's own LLM in
    the system prompt) — e.g. ``"after recon phase complete"``."""


class Role(BaseModel):
    """A specialist agent persona.

    Roles are immutable once loaded — pass a ``RoleRegistry`` around
    rather than mutating ``Role`` instances at runtime.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    """Stable lowercase snake-case identifier, e.g. ``recon_analyst``.

    Used as the audit ``role`` field and as the key in
    ``can_handoff_to``. Once published, ids must never change.
    """

    name: str
    """Human-readable name shown in the dashboard."""

    persona_prompt_path: str
    """Path to the Markdown system-prompt fragment.

    Resolved relative to the repository root. Loader checks the file
    exists at startup.
    """

    allowed_tools: list[str] = Field(default_factory=list)
    """Glob patterns of tool names this role may invoke.

    Empty list means *no tools* — useful for a Reporter that only reads
    findings.
    """

    denied_tools: list[str] = Field(default_factory=list)
    """Glob patterns that override ``allowed_tools``.

    Useful for "everything in recon_* except the destructive
    ``recon_active_scan``".
    """

    allowed_phases: list[Phase] = Field(default_factory=list)
    """PTES phases this role may act in. Empty means *all phases*."""

    can_handoff_to: list[RoleHandoff] = Field(default_factory=list)
    """Outgoing handoff edges. Validated at registry load: every ``to``
    must reference another loaded role id."""

    capability_guards: RoleCapabilityGuard = Field(default_factory=RoleCapabilityGuard)

    llm_model_hint: str = ""
    """Optional model override (e.g. small local model for recon, large
    cloud model for exploit dev). Empty means use the loop default."""

    # ── Validators ────────────────────────────────────────────────────

    @field_validator("id")
    @classmethod
    def _id_is_lowercase_snake(cls, v: str) -> str:
        if not v:
            raise ValueError("role id must be non-empty")
        if not v.replace("_", "").isalnum():
            raise ValueError(f"role id must be lowercase snake_case alnum, got {v!r}")
        if v != v.lower():
            raise ValueError(f"role id must be lowercase, got {v!r}")
        return v

    @field_validator("allowed_tools", "denied_tools")
    @classmethod
    def _patterns_nonempty(cls, v: list[str]) -> list[str]:
        for p in v:
            if not isinstance(p, str) or not p.strip():
                raise ValueError(f"empty tool pattern in {v!r}")
        return v
