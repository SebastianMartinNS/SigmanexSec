"""
agent/run_modes.py — RunMode enum + Plan data model.

Used by the orchestrator and the dashboard to control how tool calls
are dispatched (no-exec / autonomous / human-gated).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from core.time_utils import utcnow as _sap_utcnow


class RunMode(StrEnum):
    PLANNING  = "planning"
    EXECUTION = "execution"
    STEP      = "step"


class PlanStep(BaseModel):
    step_id: str = Field(default_factory=lambda: f"s_{uuid.uuid4().hex[:8]}")
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    estimated_duration_seconds: int = 0
    requires_sudo: bool = False
    scope_check: str = "unknown"   # ok | violation | unknown
    depends_on: list[str] = Field(default_factory=list)
    status: str = "proposed"        # proposed | approved | rejected | skipped | promoted


class PlanPhase(BaseModel):
    phase: str
    rationale: str = ""
    steps: list[PlanStep] = Field(default_factory=list)


class Plan(BaseModel):
    plan_id: str = Field(default_factory=lambda: f"p_{uuid.uuid4().hex[:12]}")
    engagement_id: str
    objective: str
    generated_at: datetime = Field(default_factory=_sap_utcnow)
    model: str = ""
    mode: RunMode = RunMode.PLANNING
    phases: list[PlanPhase] = Field(default_factory=list)
    risks: list[dict[str, Any]] = Field(default_factory=list)
    approval_status: str = "draft"   # draft | approved | rejected | promoted

    def append_step(
        self,
        tool: str,
        args: dict[str, Any],
        rationale: str = "",
        phase: str = "reconnaissance",
        requires_sudo: bool = False,
        scope_check: str = "unknown",
    ) -> PlanStep:
        # Find or create phase
        ph = next((p for p in self.phases if p.phase == phase), None)
        if ph is None:
            ph = PlanPhase(phase=phase)
            self.phases.append(ph)
        step = PlanStep(
            tool=tool, args=args, rationale=rationale,
            requires_sudo=requires_sudo, scope_check=scope_check,
        )
        ph.steps.append(step)
        return step
