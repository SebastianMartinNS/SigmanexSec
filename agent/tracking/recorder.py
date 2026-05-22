"""
agent/tracking/recorder.py — Bridge between the orchestrator loop and the
v3.0 audit chain.

The recorder owns the lifecycle of an :class:`AgentStep` for one iteration
of the agentic loop. Producers (the orchestrator) call ``begin_step`` once
per iteration, then ``record_plan`` / ``record_action`` / ``record_observation``
/ ``record_reflection`` as the iteration progresses, and finally ``end_step``
to flush the step into the audit log.

Each lifecycle method *also* emits a fine-grained audit event so that the
hash chain captures every decision in chronological order, not only the
aggregated step:

    iteration begin
      ┌── llm_prompt_sent      (record_llm_prompt)
      ├── llm_response_received(record_llm_response)
      ├── llm_reasoning        (record_llm_reasoning, optional)
      ├── tool dispatch        (existing executor audit, untouched)
      ├── reflection_completed (record_reflection, optional)
      └── agent_step           (end_step → aggregated record)

The recorder never blocks: it pushes into the existing
:class:`core.audit_log.AuditLog` queue. When ``SAP_V3_TRACKING_V2`` is off
(default for v3.0.0-rc1) the recorder degrades to a no-op so the legacy
behaviour is unchanged.
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from agent.tracking.agent_step import AgentStep, AgentStepState
from core.models import Phase
from core.time_utils import utcnow as _sap_utcnow
from core.tracking import (
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

if TYPE_CHECKING:
    from core.audit_log import AuditLog

_log = logging.getLogger(__name__)


def _flag_enabled() -> bool:
    """``SAP_V3_TRACKING_V2`` master switch.

    Default OFF in v3.0.0-rc1 so the existing 530 tests stay green. Flipped
    ON for rc2 once :pep:`A` is fully wired into the orchestrator.
    """
    return os.environ.get("SAP_V3_TRACKING_V2", "0") not in ("", "0", "false", "False")


class _NullRecorder:
    """No-op stand-in used when tracking is disabled. Mirrors the public
    surface of :class:`AgentStepRecorder` exactly so callers can hold a
    single reference type."""

    def __init__(self) -> None:
        self.current: AgentStep | None = None

    async def begin_step(self, **kwargs: Any) -> AgentStep:  # noqa: D401 - protocol
        # Return a throw-away step so callers can read ``.step_id`` without
        # branching. Nothing is persisted.
        return AgentStep(run_id=str(kwargs.get("run_id", "")), engagement_id="-")

    async def record_plan(self, *_, **__) -> None: ...
    async def record_llm_prompt(self, *_, **__) -> None: ...
    async def record_llm_response(self, *_, **__) -> None: ...
    async def record_llm_reasoning(self, *_, **__) -> None: ...
    async def record_action(self, *_, **__) -> None: ...
    async def record_observation(self, *_, **__) -> None: ...
    async def record_reflection(self, *_, **__) -> None: ...
    async def record_state_transition(self, *_, **__) -> None: ...
    async def record_phase_transition(self, *_, **__) -> None: ...
    async def record_role_handoff(self, *_, **__) -> None: ...
    async def end_step(self, *_, **__) -> None: ...


class AgentStepRecorder:
    """Bridges agent-loop hooks into ``AuditLog`` writes.

    One instance per ``Orchestrator`` (or, in the multi-agent topology of
    Milestone C, one per role-scoped sub-loop). Each ``begin_step`` rotates
    ``self.current`` to a fresh :class:`AgentStep`; the trailing ``end_step``
    flushes it into the BLAKE2b chain.
    """

    def __init__(
        self,
        *,
        audit_log: "AuditLog | None",
        run_id: str,
        engagement_id: str = "-",
        role: str = "legacy_monolithic",
    ) -> None:
        self._audit = audit_log
        self._run_id = run_id
        self._engagement_id = engagement_id or "-"
        self._role = role
        self.current: AgentStep | None = None

    # ------------------------------------------------------------------
    # Construction shortcut: hand back the right recorder kind based on
    # the env flag. Keeps the orchestrator constructor branch-free.
    # ------------------------------------------------------------------

    @classmethod
    def get(
        cls,
        *,
        audit_log: "AuditLog | None",
        run_id: str,
        engagement_id: str = "-",
        role: str = "legacy_monolithic",
    ) -> "AgentStepRecorder | _NullRecorder":
        if not _flag_enabled() or audit_log is None:
            return _NullRecorder()
        return cls(
            audit_log=audit_log,
            run_id=run_id,
            engagement_id=engagement_id,
            role=role,
        )

    # ------------------------------------------------------------------
    # Step lifecycle
    # ------------------------------------------------------------------

    async def begin_step(
        self,
        *,
        iteration: int,
        phase: Phase | str = Phase.SCANNING,
        state_before: dict[str, Any] | None = None,
    ) -> AgentStep:
        if isinstance(phase, str):
            try:
                phase_value = Phase(phase)
            except ValueError:
                phase_value = Phase.SCANNING
        else:
            phase_value = phase
        step = AgentStep(
            run_id=self._run_id,
            engagement_id=self._engagement_id,
            role=self._role,
            phase=phase_value,
            iteration=iteration,
            state_before=state_before or {},
        )
        self.current = step
        return step

    async def record_plan(self, plan_text: str) -> None:
        if self.current is None:
            return
        self.current.plan = plan_text
        self.current.status = AgentStepState.PLANNED

    async def record_action(self, action: dict[str, Any]) -> None:
        if self.current is None:
            return
        self.current.action = action
        self.current.status = AgentStepState.ACTING

    async def record_observation(self, observation: dict[str, Any]) -> None:
        if self.current is None:
            return
        self.current.observation = observation
        self.current.status = AgentStepState.OBSERVED

    async def record_reflection(
        self,
        reflection_text: str,
        *,
        mode: str = "sync",
        emit_event: bool = True,
    ) -> None:
        if self.current is None:
            return
        self.current.reflection = reflection_text
        self.current.status = AgentStepState.REFLECTED
        if emit_event:
            await self._write_safe(make_reflection_event(
                engagement_id=self._engagement_id,
                run_id=self._run_id,
                role=self._role,
                step_id=self.current.step_id,
                reflection_text=reflection_text,
                reflection_chars=len(reflection_text),
                mode=mode,
            ))

    async def end_step(
        self,
        *,
        state_after: dict[str, Any] | None = None,
        error: str = "",
    ) -> None:
        if self.current is None:
            return
        self.current.state_after = state_after or {}
        self.current.ended_at = _sap_utcnow()
        self.current.status = (
            AgentStepState.FAILED if error else AgentStepState.CLOSED
        )
        self.current.error = error
        await self._write_safe(make_agent_step_event(
            engagement_id=self._engagement_id,
            step_dump=self.current.model_dump(mode="json"),
        ))
        # v3 metrics: count this step (always-on counter; null when
        # prometheus_client missing).
        try:
            from core.observability import get_metrics
            get_metrics().agent_steps_total.labels(
                role=self.current.role,
                phase=str(self.current.phase),
            ).inc()
        except Exception:  # pragma: no cover - metrics must never break loop
            pass
        self.current = None

    # ------------------------------------------------------------------
    # Per-step fine-grained events
    # ------------------------------------------------------------------

    async def record_llm_prompt(
        self,
        *,
        messages: list[dict[str, Any]] | str,
        system: str,
        provider: str,
        model: str,
        temperature: float,
        seed: int | None,
        tools_offered: int,
        include_payload: bool = False,
    ) -> str:
        """Returns the ``prompt_hash`` so callers can persist it on the step."""
        ph = prompt_hash(messages, system=system)
        if self.current is not None:
            self.current.prompt_hash = ph
            self.current.llm_provider = provider
            self.current.llm_model = model
            self.current.llm_temperature = temperature
            self.current.llm_seed = seed
        payload = None
        if include_payload:
            try:
                import json as _json
                if isinstance(messages, str):
                    payload = messages
                else:
                    payload = _json.dumps(messages, ensure_ascii=False)
            except Exception:  # pragma: no cover
                payload = None
        await self._write_safe(make_llm_prompt_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            role=self._role,
            provider=provider,
            model=model,
            prompt_hash_hex=ph,
            messages_count=len(messages) if isinstance(messages, list) else 1,
            system_chars=len(system),
            tools_offered=tools_offered,
            temperature=temperature,
            seed=seed,
            prompt_payload=payload,
        ))
        return ph

    async def record_llm_response(
        self,
        *,
        response_hash_hex: str,
        provider: str,
        model: str,
        stop_reason: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float,
        tool_calls_count: int,
        response_payload: str | None = None,
    ) -> None:
        if self.current is not None:
            self.current.response_hash = response_hash_hex
            self.current.input_tokens = input_tokens
            self.current.output_tokens = output_tokens
        await self._write_safe(make_llm_response_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            role=self._role,
            provider=provider,
            model=model,
            response_hash_hex=response_hash_hex,
            stop_reason=stop_reason,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            tool_calls_count=tool_calls_count,
            response_payload=response_payload,
        ))
        try:
            from core.observability import get_metrics
            m = get_metrics()
            m.llm_calls_total.labels(provider=provider, model=model).inc()
            m.llm_latency_seconds.labels(provider=provider).observe(latency_ms / 1000.0)
        except Exception:  # pragma: no cover
            pass

    async def record_llm_reasoning(
        self,
        *,
        reasoning_text: str | None,
        reasoning_source: str,
        include_text: bool = False,
    ) -> None:
        await self._write_safe(make_llm_reasoning_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            role=self._role,
            reasoning_text=reasoning_text if include_text else None,
            reasoning_chars=len(reasoning_text or ""),
            reasoning_source=reasoning_source,
        ))

    async def record_state_transition(
        self,
        *,
        src_state: str,
        dst_state: str,
        reason: str = "",
    ) -> None:
        await self._write_safe(make_state_transition_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            role=self._role,
            src_state=src_state,
            dst_state=dst_state,
            reason=reason,
        ))

    async def record_phase_transition(
        self,
        *,
        src_phase: str,
        dst_phase: str,
        reason: str = "",
    ) -> None:
        await self._write_safe(make_phase_transition_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            role=self._role,
            src_phase=src_phase,
            dst_phase=dst_phase,
            reason=reason,
        ))

    async def record_role_handoff(
        self,
        *,
        dst_role: str,
        reason: str,
        context_ref: str = "",
    ) -> None:
        src_role = self._role
        await self._write_safe(make_role_handoff_event(
            engagement_id=self._engagement_id,
            run_id=self._run_id,
            src_role=src_role,
            dst_role=dst_role,
            handoff_reason=reason,
            context_ref=context_ref,
        ))
        try:
            from core.observability import get_metrics
            get_metrics().role_handoffs_total.labels(src=src_role, dst=dst_role).inc()
        except Exception:  # pragma: no cover
            pass
        # The recorder's notion of "current role" follows the handoff so any
        # events emitted after this call are attributed to the new role.
        self._role = dst_role

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _write_safe(self, entry: Any) -> None:
        if self._audit is None:
            return
        try:
            # Wrap sensitive details (prompt_payload, response_payload,
            # reasoning_text, reflection_text) with Fernet at-rest. No-op
            # when ``SAP_AUDIT_ENCRYPT=0`` or no key resolves.
            from core.tracking.encrypted_sink import encrypt_entry_in_place
            encrypt_entry_in_place(entry)
        except Exception as exc:  # pragma: no cover
            _log.warning("AgentStepRecorder.encrypt failed: %s", exc)
        try:
            await self._audit.write(entry)
        except Exception as exc:  # pragma: no cover - audit must not crash loop
            _log.warning("AgentStepRecorder.write failed: %s", exc)
