"""
agent/state/machine.py — Explicit ReAct state machine.

The legacy single-agent loop carried its state implicitly in
``iteration``, ``self._tool_call_counts`` and ``self._last_thinking``.
That worked for one agent but made handoff and reflection invisible to
the audit chain.

This module gives every run an explicit state at every moment. The
state machine raises :class:`IllegalTransition` on invalid hops so a
bug in the Coordinator surfaces immediately rather than corrupting the
audit chain.
"""
from __future__ import annotations

from enum import StrEnum


class AgentState(StrEnum):
    IDLE = "idle"
    PLANNING = "planning"
    ACTING = "acting"
    OBSERVING = "observing"
    REFLECTING = "reflecting"
    HANDING_OFF = "handing_off"
    DONE = "done"
    FAILED = "failed"


# Codified ReAct transitions. ``set()`` means a terminal state.
_TRANSITIONS: dict[AgentState, frozenset[AgentState]] = {
    AgentState.IDLE: frozenset({AgentState.PLANNING}),
    AgentState.PLANNING: frozenset({
        AgentState.ACTING, AgentState.HANDING_OFF, AgentState.DONE, AgentState.FAILED,
    }),
    AgentState.ACTING: frozenset({AgentState.OBSERVING, AgentState.FAILED}),
    AgentState.OBSERVING: frozenset({
        AgentState.REFLECTING, AgentState.PLANNING, AgentState.FAILED,
    }),
    AgentState.REFLECTING: frozenset({
        AgentState.PLANNING, AgentState.HANDING_OFF, AgentState.DONE, AgentState.FAILED,
    }),
    AgentState.HANDING_OFF: frozenset({AgentState.IDLE, AgentState.FAILED}),
    AgentState.DONE: frozenset(),
    AgentState.FAILED: frozenset(),
}


class IllegalTransition(Exception):
    """Raised when a hop is not in :data:`_TRANSITIONS`.

    The exception message names both endpoints so the audit chain
    captures the offending hop without the caller having to format it.
    """


class AgentStateMachine:
    """Mutable cursor walking :data:`_TRANSITIONS`.

    One instance per run. Thread-unsafe by design — the loop is
    single-threaded per run; if you need parallel sub-runs (multi-agent
    handoff in flight) construct one machine per sub-run and let the
    Coordinator gate progression.
    """

    __slots__ = ("_state", "_history")

    def __init__(self, *, initial: AgentState = AgentState.IDLE) -> None:
        self._state = initial
        self._history: list[tuple[AgentState, AgentState, str]] = []

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def history(self) -> list[tuple[AgentState, AgentState, str]]:
        """Immutable copy of ``(src, dst, reason)`` transitions so far."""
        return list(self._history)

    def is_terminal(self) -> bool:
        return self._state in (AgentState.DONE, AgentState.FAILED)

    def can_transition(self, dst: AgentState) -> bool:
        return dst in _TRANSITIONS[self._state]

    # ------------------------------------------------------------------
    # Mutate
    # ------------------------------------------------------------------

    def transition(self, dst: AgentState, *, reason: str = "") -> None:
        """Advance to *dst* or raise :class:`IllegalTransition`."""
        if dst not in _TRANSITIONS[self._state]:
            allowed = sorted(s.value for s in _TRANSITIONS[self._state])
            raise IllegalTransition(
                f"illegal transition {self._state.value} → {dst.value} "
                f"(allowed from {self._state.value}: {allowed})"
            )
        self._history.append((self._state, dst, reason))
        self._state = dst

    def fail(self, *, reason: str = "") -> None:
        """Shortcut for ``transition(FAILED, ...)``. Always legal."""
        self._history.append((self._state, AgentState.FAILED, reason))
        self._state = AgentState.FAILED
