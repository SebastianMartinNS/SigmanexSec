"""
tests/test_v3_state_machine.py — Milestone C3 acceptance.

Exercises the explicit ReAct state machine. Every legal transition must
pass; every illegal hop must raise. The history must capture the full
walk so the audit chain can correlate STATE_TRANSITION events 1:1.
"""
from __future__ import annotations

import pytest

from agent.state import AgentState, AgentStateMachine, IllegalTransition


def test_initial_state_is_idle():
    sm = AgentStateMachine()
    assert sm.state is AgentState.IDLE
    assert not sm.is_terminal()


def test_legal_react_cycle():
    sm = AgentStateMachine()
    sm.transition(AgentState.PLANNING, reason="start")
    sm.transition(AgentState.ACTING, reason="call tool")
    sm.transition(AgentState.OBSERVING, reason="got result")
    sm.transition(AgentState.REFLECTING, reason="evaluate")
    sm.transition(AgentState.PLANNING, reason="next step")
    assert sm.state is AgentState.PLANNING
    assert len(sm.history) == 5


def test_illegal_transition_raises():
    sm = AgentStateMachine()
    # IDLE → ACTING is illegal (must go through PLANNING first).
    with pytest.raises(IllegalTransition, match="illegal transition"):
        sm.transition(AgentState.ACTING)


def test_done_is_terminal():
    sm = AgentStateMachine()
    sm.transition(AgentState.PLANNING)
    sm.transition(AgentState.DONE)
    assert sm.is_terminal()
    # No outgoing transitions from DONE.
    with pytest.raises(IllegalTransition):
        sm.transition(AgentState.PLANNING)


def test_failed_is_terminal_trap():
    sm = AgentStateMachine()
    sm.fail(reason="catastrophic")
    assert sm.state is AgentState.FAILED
    assert sm.is_terminal()


def test_fail_always_legal_from_any_state():
    sm = AgentStateMachine()
    sm.transition(AgentState.PLANNING)
    sm.transition(AgentState.ACTING)
    sm.fail(reason="exception during dispatch")
    assert sm.state is AgentState.FAILED


def test_handoff_flow():
    """The full handoff cycle ends back in IDLE so the new role can start
    a fresh PLANNING → ACTING walk."""
    sm = AgentStateMachine()
    sm.transition(AgentState.PLANNING)
    sm.transition(AgentState.HANDING_OFF)
    sm.transition(AgentState.IDLE)
    sm.transition(AgentState.PLANNING)
    assert sm.state is AgentState.PLANNING


def test_can_transition_predicate():
    sm = AgentStateMachine()
    assert sm.can_transition(AgentState.PLANNING)
    assert not sm.can_transition(AgentState.ACTING)


def test_history_records_each_hop():
    sm = AgentStateMachine()
    sm.transition(AgentState.PLANNING, reason="a")
    sm.transition(AgentState.ACTING, reason="b")
    assert sm.history == [
        (AgentState.IDLE, AgentState.PLANNING, "a"),
        (AgentState.PLANNING, AgentState.ACTING, "b"),
    ]
    # History is a copy — mutating the returned list does not corrupt
    # the machine.
    sm.history.append(("x", "y", "tamper"))  # type: ignore[arg-type]
    assert len(sm.history) == 2
