"""
agent/coordinator.py — Multi-agent team orchestrator (Milestone C).

Sits *above* :class:`AgenticLoop` (Milestone B2) and is responsible for
choosing which role runs next. The loop is single-agent; the
Coordinator threads multiple loops together via :class:`AgentContext`
handoffs.

Gated by the ``SAP_AGENT_MODE`` env (default ``single``). When
``single``, the Coordinator wraps the legacy monolithic system prompt
in a single fake "role" so the rest of the pipeline (audit, state
machine, recorder) sees a uniform shape without any behaviour change
for existing v2.3 deployments.
"""
from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent.coordination.handoff import AgentContext, CompletedTask
from agent.roles import Role, get_registry
from agent.state import AgentState, AgentStateMachine
from core.models import Phase
from core.role_validator import RoleViolation, get_role_validator
from core.time_utils import utcnow as _sap_utcnow

if TYPE_CHECKING:                                  # pragma: no cover
    from agent.tracking.recorder import AgentStepRecorder, _NullRecorder

_log = logging.getLogger(__name__)


def agent_mode() -> str:
    """Return ``"single"`` (default) or ``"multi"``.

    v3.0.0 ships with ``single``. ``multi`` is opt-in until v3.1 makes
    it the default after community feedback. See [[project_v3_decisions]].
    """
    val = (os.environ.get("SAP_AGENT_MODE", "single") or "").strip().lower()
    if val in ("multi", "single"):
        return val
    return "single"


# Type alias for the per-role driver the Coordinator calls. The
# Coordinator hands the role + handoff context; the driver runs one
# slice of the engagement and returns the closure context for the next
# handoff (or None when it terminates).
RoleDriver = Callable[
    [str, AgentContext | None],
    Awaitable[AgentContext | None],
]


class Coordinator:
    """Schedule role-to-role work for one engagement run.

    The Coordinator does **not** drive the LLM directly — it asks a
    ``RoleDriver`` (the orchestrator's per-role facade) to run the
    selected role and report back. This keeps the orchestrator free to
    layer its memory / adaptive / approval gate machinery on each role
    without the Coordinator caring.
    """

    def __init__(
        self,
        *,
        engagement_id: str,
        run_id: str | None = None,
        driver: RoleDriver,
        recorder: "AgentStepRecorder | _NullRecorder | None" = None,
        initial_role: str = "planner",
        initial_phase: Phase = Phase.SCOPING,
        max_handoffs: int = 32,
    ) -> None:
        self._engagement_id = engagement_id
        self._run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
        self._driver = driver
        self._recorder = recorder
        self._initial_role = initial_role
        self._current_role = initial_role
        self._initial_phase = initial_phase
        self._current_phase = initial_phase
        self._max_handoffs = max_handoffs
        self._sm = AgentStateMachine(initial=AgentState.IDLE)
        self._registry = get_registry()
        self._role_validator = get_role_validator()

    # ------------------------------------------------------------------
    # Properties (read-only)
    # ------------------------------------------------------------------

    @property
    def state(self) -> AgentState:
        return self._sm.state

    @property
    def current_role(self) -> str:
        return self._current_role

    @property
    def current_phase(self) -> Phase:
        return self._current_phase

    @property
    def state_history(self) -> list[tuple[AgentState, AgentState, str]]:
        return self._sm.history

    # ------------------------------------------------------------------
    # Drive
    # ------------------------------------------------------------------

    async def run(self) -> str:
        """Drive role-to-role handoffs until DONE / FAILED / cap hit.

        Returns the final ``role_id`` that terminated the run so the
        caller can identify the reporter that closed the engagement.
        """
        self._sm.transition(AgentState.PLANNING, reason="coordinator.start")
        ctx: AgentContext | None = None
        for hop in range(self._max_handoffs):
            try:
                role = self._role(self._current_role)
            except RoleViolation as exc:
                self._sm.fail(reason=str(exc))
                return self._current_role
            # Drive one role's slice.
            self._sm.transition(AgentState.ACTING, reason=f"drive {role.id}")
            try:
                closure = await self._driver(role.id, ctx)
            except Exception as exc:
                self._sm.fail(reason=f"driver exception: {exc!r}")
                _log.exception("Coordinator driver failed for role %s", role.id)
                return role.id
            self._sm.transition(AgentState.OBSERVING, reason=f"closure {role.id}")
            self._sm.transition(AgentState.REFLECTING, reason="post-role reflect")
            if closure is None:
                self._sm.transition(AgentState.DONE, reason="role terminal")
                return role.id
            # Validate handoff against the source role's catalog edge.
            try:
                if self._role_validator is not None:
                    self._role_validator.assert_handoff_allowed(role.id, closure.target_role)
            except RoleViolation as exc:
                self._sm.fail(reason=str(exc))
                return role.id
            # Phase transitions are surfaced separately so the dashboard
            # can render a PTES timeline.
            if closure.current_phase != self._current_phase:
                if self._recorder is not None:
                    await self._recorder.record_phase_transition(
                        src_phase=str(self._current_phase),
                        dst_phase=str(closure.current_phase),
                        reason=closure.handoff_reason,
                    )
                self._current_phase = closure.current_phase
            # Audit the handoff.
            self._sm.transition(
                AgentState.HANDING_OFF,
                reason=f"{role.id}→{closure.target_role}",
            )
            if self._recorder is not None:
                await self._recorder.record_role_handoff(
                    dst_role=closure.target_role,
                    reason=closure.handoff_reason,
                    context_ref=closure.memory_snapshot_ref,
                )
            # Switch role.
            self._sm.transition(AgentState.IDLE, reason="handoff complete")
            self._sm.transition(AgentState.PLANNING, reason=f"start {closure.target_role}")
            self._current_role = closure.target_role
            ctx = closure
        # Hit the handoff cap → terminate with the most recent role.
        self._sm.fail(reason=f"max_handoffs={self._max_handoffs} exceeded")
        return self._current_role

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _role(self, role_id: str) -> Role:
        if role_id == "legacy_monolithic":
            return _legacy_monolithic_role(self._initial_phase)
        return self._registry.require(role_id)


def _legacy_monolithic_role(phase: Phase) -> Role:
    """Synthesize a Role that wraps the v2.3 single-agent prompt.

    Used when ``SAP_AGENT_MODE=single`` so the rest of the pipeline
    (state machine, recorder, audit) sees a uniform Role shape even
    though no YAML is involved.
    """
    persona_path = Path(__file__).resolve().parent / "prompts" / "system_prompt.md"
    rel = str(persona_path.relative_to(Path(__file__).resolve().parents[1]))
    from agent.roles.schema import Role as _Role, RoleCapabilityGuard
    return _Role(
        id="legacy_monolithic",
        name="Single-Agent (legacy v2.3)",
        persona_prompt_path=rel,
        allowed_tools=["*"],
        denied_tools=[],
        allowed_phases=[phase] if phase is not None else [],
        can_handoff_to=[],
        capability_guards=RoleCapabilityGuard(),
    )


# ----------------------------------------------------------------------
# Convenience: stub driver useful for tests + dry runs
# ----------------------------------------------------------------------


def make_dummy_driver(
    *,
    handoff_plan: list[tuple[str, Phase, str]] | None = None,
) -> RoleDriver:
    """A driver that returns a pre-canned handoff plan.

    ``handoff_plan`` is ``[(target_role, target_phase, reason), ...]``.
    Useful for testing the Coordinator without spinning up a real LLM.
    The driver terminates (returns None) when the plan is exhausted.
    """
    plan = list(handoff_plan or [])

    async def _driver(role_id: str, _ctx: AgentContext | None) -> AgentContext | None:
        if not plan:
            return None
        target, phase, reason = plan.pop(0)
        return AgentContext(
            engagement_id="dummy",
            run_id="dummy",
            current_phase=phase,
            parent_role=role_id,
            target_role=target,
            handoff_reason=reason,
            completed_tasks=[CompletedTask(description=f"{role_id} did its part", tool_calls_made=1)],
        )

    return _driver
