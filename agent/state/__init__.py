"""
agent/state/ — Formal state machine for the agentic loop (Milestone C3).

A single agent run walks the ReAct cycle as

    IDLE → PLANNING → ACTING → OBSERVING → REFLECTING → (PLANNING | HANDING_OFF | DONE)

with FAILED as a terminal trap. The transitions are codified in
``_TRANSITIONS`` so a runaway run cannot silently slip into a state the
audit does not record.

Public API:

    from agent.state import AgentState, AgentStateMachine, IllegalTransition
"""
from __future__ import annotations

from agent.state.machine import AgentState, AgentStateMachine, IllegalTransition

__all__ = ["AgentState", "AgentStateMachine", "IllegalTransition"]
