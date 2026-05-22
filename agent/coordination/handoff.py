"""
agent/coordination/handoff.py — Structured handoff payload (Milestone C5).

When one role finishes its slice of the work and passes the baton to
another, the bag of context that travels between them needs a stable
shape so the receiving role can pick up cold. :class:`AgentContext` is
that shape.

The payload is intentionally *summarised*: the full conversation lives
in :class:`MemoryManager` (referenced by ``memory_snapshot_ref``); only
the decision-relevant slice rides on the handoff so the Coordinator can
log it in the audit chain without exploding entry sizes.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from core.models import Phase
from core.time_utils import utcnow as _sap_utcnow


class FindingRef(BaseModel):
    """Reference to a finding produced earlier in the run.

    Just the *handle*, not the whole finding — the receiving role can
    fetch the full record via ``get_finding(finding_id)`` when needed.
    """

    model_config = ConfigDict(frozen=True)

    finding_id: str
    severity: str
    summary: str = ""


class CompletedTask(BaseModel):
    """One discrete unit of work the source role completed."""

    model_config = ConfigDict(frozen=True)

    task_id: str = Field(default_factory=lambda: f"task_{uuid.uuid4().hex[:12]}")
    description: str
    tool_calls_made: int = 0
    findings_produced: list[str] = Field(default_factory=list)


class AgentContext(BaseModel):
    """The bag of context that travels on a handoff.

    The Coordinator builds one of these when a source role declares it
    is done; the destination role receives it as part of its starting
    system prompt (rendered to a compact JSON block).
    """

    model_config = ConfigDict(frozen=True)

    handoff_id: str = Field(default_factory=lambda: f"hand_{uuid.uuid4().hex[:12]}")
    engagement_id: str
    run_id: str
    timestamp: datetime = Field(default_factory=_sap_utcnow)

    current_phase: Phase
    parent_role: str
    target_role: str
    handoff_reason: str = ""

    findings_so_far: list[FindingRef] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    completed_tasks: list[CompletedTask] = Field(default_factory=list)

    memory_snapshot_ref: str = ""
    """Path / URI to the MemoryManager dump the receiving role should
    resume from. Empty when the receiver is expected to start from a
    fresh memory."""

    def to_prompt_block(self) -> str:
        """Render as a compact, human-readable system-prompt fragment.

        Used by the Coordinator to splice the handoff into the
        destination role's first system message.
        """
        lines: list[str] = []
        lines.append(f"## Handoff from `{self.parent_role}` → `{self.target_role}`")
        lines.append(f"- Engagement: `{self.engagement_id}` (phase: `{self.current_phase}`)")
        if self.handoff_reason:
            lines.append(f"- Reason: {self.handoff_reason}")
        if self.completed_tasks:
            lines.append(f"- Completed by previous role: {len(self.completed_tasks)} task(s)")
            for t in self.completed_tasks[:5]:
                lines.append(f"  - {t.description} ({t.tool_calls_made} tool calls)")
        if self.findings_so_far:
            lines.append(f"- Findings to date ({len(self.findings_so_far)}):")
            for f in self.findings_so_far[:10]:
                head = f.summary[:80] if f.summary else f.finding_id
                lines.append(f"  - [{f.severity}] {head}")
        if self.open_questions:
            lines.append("- Open questions to answer or hand back:")
            for q in self.open_questions[:5]:
                lines.append(f"  - {q}")
        if self.memory_snapshot_ref:
            lines.append(f"- Memory snapshot: `{self.memory_snapshot_ref}`")
        return "\n".join(lines)
