"""
core/tracking/ — v3.0 cognitive tracking layer.

Composes on top of the existing :mod:`core.audit_log` chokepoint without
modifying its signature. Produces ``AuditEntry`` instances with stable
``action`` values from :mod:`core.audit_events` and versioned ``details``
payloads.

Public API:

    from core.tracking import (
        make_llm_prompt_event,
        make_llm_response_event,
        make_llm_reasoning_event,
        make_agent_step_event,
        make_role_handoff_event,
        make_phase_transition_event,
        make_reflection_event,
        make_state_transition_event,
        prompt_hash,
    )
"""
from __future__ import annotations

from core.tracking.events import (
    make_agent_step_event,
    make_llm_prompt_event,
    make_llm_reasoning_event,
    make_llm_response_event,
    make_phase_transition_event,
    make_reflection_event,
    make_role_handoff_event,
    make_state_transition_event,
    prompt_hash,
)

__all__ = [
    "make_agent_step_event",
    "make_llm_prompt_event",
    "make_llm_reasoning_event",
    "make_llm_response_event",
    "make_phase_transition_event",
    "make_reflection_event",
    "make_role_handoff_event",
    "make_state_transition_event",
    "prompt_hash",
]
