"""
agent/tracking/agent_step.py — Atomic ReAct step record (v3.0).

A single ``AgentStep`` captures one iteration of the orchestrator loop:
*plan → action → observation → reflection → state delta*. Recorded into
the existing BLAKE2b audit chain so any compliance reviewer can reconstruct
the chain of reasoning that led to each tool invocation.

The model is intentionally provider-neutral: ``prompt_hash`` / ``response_hash``
point at the encrypted-at-rest payload (handled by
:mod:`core.tracking.encrypted_sink`), and ``llm_seed`` / ``llm_temperature``
record what would be needed for a deterministic replay (see ``scripts/replay_run.py``).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from core.models import Phase
from core.time_utils import utcnow as _sap_utcnow


class AgentStepState(StrEnum):
    """Lifecycle of an individual step.

    The orchestrator-wide state machine lives in ``agent/state/machine.py``
    (Milestone C); this enum is the *intra-step* state for the recorder
    to know which phase of the ReAct cycle the producer is currently in.
    """

    OPEN = "open"               # begin_step called, plan not yet recorded
    PLANNED = "planned"         # rationale captured
    ACTING = "acting"           # tool dispatched
    OBSERVED = "observed"       # tool result captured
    REFLECTED = "reflected"     # reflection text attached (optional)
    CLOSED = "closed"           # end_step called → flushed to audit log
    FAILED = "failed"           # error path; closed with failure marker


class AgentStep(BaseModel):
    step_id: str = Field(default_factory=lambda: f"as_{uuid.uuid4().hex[:12]}")
    run_id: str
    engagement_id: str
    role: str = "legacy_monolithic"   # default for SAP_AGENT_MODE=single
    phase: Phase = Phase.SCANNING
    iteration: int = 0

    # ReAct slots ---------------------------------------------------------
    state_before: dict[str, Any] = Field(default_factory=dict)
    plan: str = ""
    action: dict[str, Any] = Field(default_factory=dict)
    observation: dict[str, Any] = Field(default_factory=dict)
    reflection: str = ""
    state_after: dict[str, Any] = Field(default_factory=dict)

    # Provenance ----------------------------------------------------------
    prompt_hash: str = ""
    response_hash: str = ""
    llm_provider: str = ""
    llm_model: str = ""
    llm_seed: int | None = None
    llm_temperature: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0

    # Lifecycle -----------------------------------------------------------
    status: AgentStepState = AgentStepState.OPEN
    started_at: datetime = Field(default_factory=_sap_utcnow)
    ended_at: datetime | None = None
    error: str = ""

    def duration_seconds(self) -> float | None:
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()
