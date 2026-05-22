"""
core/audit_events.py — Catalog of audit `AuditEntry.action` values.

Until v3.0 every call site used free-form strings (``action="tool_execute"``,
``action="decision"``, ...). This module is the single source of truth for the
stable action names so producers (orchestrator, MCP servers, GDPR jobs) and
consumers (dashboard, replay, compliance reports) agree on the vocabulary.

The enum is a ``StrEnum`` so every value serializes as the original string
and remains backward-compatible with logs written before v3.0 — no migration
required for the existing 530 tests.

Versioning: when a new event payload schema is introduced, embed the version
in ``AuditEntry.details["v"]``. Old readers ignore unknown keys; new readers
branch on ``v`` to handle the schema.
"""
from __future__ import annotations

from enum import StrEnum


class AuditAction(StrEnum):
    # ── Legacy v2.x action types (preserved verbatim for backward compat) ─

    TOOL_EXECUTE = "tool_execute"
    PRIVILEGED_TOOL_EXECUTE = "privileged_tool_execute"
    TOOL_COMPLETE = "tool_complete"
    SUDO_FAILURE = "sudo_failure"
    SANDBOX_WARN = "sandbox.warn"
    DECISION = "decision"
    GDPR_PURGE = "gdpr_purge"
    GDPR_RETENTION = "gdpr_retention"

    # ── v3.0 cognitive-tracking action types ──────────────────────────────
    #
    # These events make the agent's decision-making loop auditable end-to-end.
    # See plan: ~/.claude/plans/aloora-ho-notato-che-dazzling-fountain.md §A1.

    LLM_PROMPT_SENT = "llm_prompt_sent"
    LLM_RESPONSE_RECEIVED = "llm_response_received"
    LLM_REASONING = "llm_reasoning"
    AGENT_STEP = "agent_step"
    ROLE_HANDOFF = "role_handoff"
    PHASE_TRANSITION = "phase_transition"
    REFLECTION_COMPLETED = "reflection_completed"
    STATE_TRANSITION = "state_transition"


# Payload schema version emitted by the v3 factories. Bumped together with
# any breaking change to ``AuditEntry.details`` shape for a given action.
TRACKING_SCHEMA_V = 1
