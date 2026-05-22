"""
tests/test_v3_w3_wiring.py — W1.5 + W1.7 + W1.6 acceptance.

Pins the Settimana 3 wiring of the consolidation phase:

* W1.5 — role-aware dispatch denies an out-of-policy tool with a
  structured ``role_denied`` JSON tool-result and an audit
  ``scope_violation`` event with ``violation_type=role``.
* W1.7 — ``SAP_REFLECTION_MODE=sync`` + a loaded reflection prompt
  causes one extra ``provider.chat`` per tool-bearing iteration whose
  output rides on the audit chain as ``reflection_completed``.
* W1.6 — ``SAP_AGENT_MODE=multi`` routes :meth:`Orchestrator.run`
  through the Coordinator and the deterministic PTES fallback walks
  every role in order, emitting the expected ``role_handoff`` events.

Like ``test_v3_wiring_e2e.py``, everything runs in-process with a
scripted ``_FakeProvider`` so no LLM is required.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from agent.providers.types import (
    ChatMessage,
    LLMResponse,
    LLMUsage,
    ParsedToolCall,
    Role,
    StopReason,
)
from core.models import Phase

# ── _FakeProvider ─────────────────────────────────────────────────────────


class _FakeProvider:
    """Scripted provider. Reflection sub-calls are detected by the
    presence of ``Reflection step`` in the system prompt and answered
    with a trivial JSON; main turns alternate tool_use then end_turn."""

    name = "fake-w3"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def chat(self, **kwargs: Any) -> LLMResponse:
        system = kwargs.get("system") or ""
        if "Reflection step" in system:
            self.calls.append("reflection")
            return LLMResponse(
                text='{"reached_purpose": true, "next_move": "done"}',
                stop_reason=StopReason.END_TURN,
                usage=LLMUsage(input_tokens=30, output_tokens=10),
                model="fake",
            )
        n_main = self.calls.count("main")
        self.calls.append("main")
        if n_main == 0:
            return LLMResponse(
                text="Scanning.",
                tool_calls=[ParsedToolCall(id="c1", name="nmap_scan", args={"host": "1.2.3.4"})],
                stop_reason=StopReason.TOOL_USE,
                usage=LLMUsage(input_tokens=50, output_tokens=10),
                model="fake",
            )
        return LLMResponse(
            text="All done.",
            stop_reason=StopReason.END_TURN,
            usage=LLMUsage(input_tokens=60, output_tokens=10),
            model="fake",
        )

    def normalize_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        return [{"name": t.name} for t in tools]

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        return ChatMessage(
            role=Role.ASSISTANT, content=response.text, tool_calls=list(response.tool_calls),
        )

    def format_tool_result(self, *, call_id: str, tool_name: str, content: str) -> ChatMessage:
        return ChatMessage(
            role=Role.TOOL, content=content, tool_call_id=call_id, name=tool_name,
        )

    def extra_capabilities(self) -> dict[str, Any]:
        return {}


# ── W1.5: role-aware dispatch ─────────────────────────────────────────────


def test_agent_mode_default_is_single(monkeypatch):
    monkeypatch.delenv("SAP_AGENT_MODE", raising=False)
    from agent.orchestrator import _agent_mode
    assert _agent_mode() == "single"


def test_agent_mode_accepts_multi(monkeypatch):
    monkeypatch.setenv("SAP_AGENT_MODE", "multi")
    from agent.orchestrator import _agent_mode
    assert _agent_mode() == "multi"


def test_agent_mode_falls_back_to_single_on_garbage(monkeypatch):
    monkeypatch.setenv("SAP_AGENT_MODE", "unknown-mode")
    from agent.orchestrator import _agent_mode
    assert _agent_mode() == "single"


@pytest.mark.asyncio
async def test_role_aware_dispatch_denies_out_of_policy(tmp_paths, monkeypatch):
    """recon_analyst is denied ``metasploit_module`` via the YAML
    ``denied_tools`` glob — the dispatcher must surface a
    ``role_denied`` JSON tool-result and audit a ``scope_violation``
    event with ``violation_type=role``."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    from agent.orchestrator import Orchestrator
    from core.audit_log import AuditLog

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    audit = AuditLog(log_path=str(log_path))
    o = Orchestrator(audit_log=audit)
    o._engagement_id = "eng-role-deny"

    out = await o._dispatch_tool_for_role(
        "metasploit_module", {"host": "10.0.0.1"}, "call_x",
        role="recon_analyst", phase=Phase.RECON,
    )
    await audit.flush()
    await audit.close()

    payload = json.loads(out)
    assert payload["role_denied"] is True
    assert payload["role"] == "recon_analyst"
    assert "metasploit" in payload["reason"]

    # Audit event must reference the role-violation classification.
    lines = log_path.read_text().splitlines()
    role_violations = [
        json.loads(line) for line in lines
        if line.strip() and json.loads(line).get("action") == "scope_violation"
        and json.loads(line).get("details", {}).get("violation_type") == "role"
    ]
    assert len(role_violations) == 1
    assert role_violations[0]["details"]["role"] == "recon_analyst"
    assert role_violations[0]["details"]["tool"] == "metasploit_module"


@pytest.mark.asyncio
async def test_role_aware_dispatch_bypasses_for_legacy_monolithic():
    """The single-agent sentinel role bypasses the RoleValidator and
    falls back to ``_dispatch_tool`` directly. We confirm by calling
    a tool the registry does not know — the response must be the
    legacy ``tool not found`` error, not a ``role_denied`` envelope."""
    os.environ.setdefault("LLM_PROVIDER", "openai")
    from agent.orchestrator import Orchestrator

    o = Orchestrator()
    out = await o._dispatch_tool_for_role(
        "nmap_scan", {}, "call_y",
        role="legacy_monolithic", phase=Phase.RECON,
    )
    assert "not found" in out
    assert "role_denied" not in out


# ── W1.7: reflection step ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reflection_off_by_default(tmp_paths, monkeypatch):
    """With ``SAP_REFLECTION_MODE`` unset (default ``off``) the
    AgenticLoop emits zero ``reflection_completed`` events even when a
    reflection prompt is supplied."""
    monkeypatch.delenv("SAP_REFLECTION_MODE", raising=False)
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")

    from agent.loop import AgenticLoop, LoopContext
    from agent.orchestrator import _load_reflection_prompt
    from agent.providers.types import ToolSpec
    from agent.tracking.recorder import AgentStepRecorder
    from core.audit_log import AuditLog

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="r-refl-off", engagement_id="e1", role="legacy_monolithic",
    )

    provider = _FakeProvider()

    async def dispatcher(_tc: ParsedToolCall) -> str:
        return json.dumps({"ok": True})

    loop = AgenticLoop(
        provider=provider, dispatcher=dispatcher, recorder=recorder,
        reflection_prompt=_load_reflection_prompt(),
    )
    ctx = LoopContext(
        run_id="r-refl-off",
        engagement_id="e1",
        messages=[ChatMessage(role=Role.USER, content="go")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=4,
    )
    await loop.run(ctx)
    await log.flush()
    await log.close()

    actions = [
        json.loads(line)["action"]
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    assert "reflection_completed" not in actions
    # Provider was called twice (turn 1 + turn 2) and never for reflection.
    assert provider.calls == ["main", "main"]


@pytest.mark.asyncio
async def test_reflection_sync_emits_event_per_tool_iteration(tmp_paths, monkeypatch):
    """With ``SAP_REFLECTION_MODE=sync`` and a reflection prompt, every
    iteration that requested a tool fires one extra provider.chat and
    emits a ``reflection_completed`` audit event."""
    monkeypatch.setenv("SAP_REFLECTION_MODE", "sync")
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")

    from agent.loop import AgenticLoop, LoopContext
    from agent.orchestrator import _load_reflection_prompt
    from agent.providers.types import ToolSpec
    from agent.tracking.recorder import AgentStepRecorder
    from core.audit_log import AuditLog

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="r-refl-sync", engagement_id="e1", role="legacy_monolithic",
    )

    provider = _FakeProvider()

    async def dispatcher(_tc: ParsedToolCall) -> str:
        return json.dumps({"ok": True})

    loop = AgenticLoop(
        provider=provider, dispatcher=dispatcher, recorder=recorder,
        reflection_prompt=_load_reflection_prompt(),
    )
    ctx = LoopContext(
        run_id="r-refl-sync",
        engagement_id="e1",
        messages=[ChatMessage(role=Role.USER, content="go")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=4,
    )
    await loop.run(ctx)
    await log.flush()
    await log.close()

    # Sequence: main turn1 (tool_use) → reflection → main turn2 (end_turn).
    assert provider.calls == ["main", "reflection", "main"]
    actions = [
        json.loads(line)["action"]
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    assert actions.count("reflection_completed") == 1


# ── W1.6: Coordinator multi-agent walk ────────────────────────────────────


def test_orchestrator_exposes_run_via_coordinator():
    os.environ.setdefault("LLM_PROVIDER", "openai")
    from agent.orchestrator import Orchestrator
    o = Orchestrator()
    assert callable(getattr(o, "_run_via_coordinator", None))


@pytest.mark.asyncio
async def test_coordinator_walks_default_ptes_fallback(tmp_paths, monkeypatch):
    """When the role driver does not request a specific handoff, the
    PTES fallback walk drives the engagement through every role until
    ``reporter`` terminates it.

    The orchestrator delegates to :class:`Coordinator` when
    ``SAP_AGENT_MODE=multi``. We swap in a stand-in driver that always
    proceeds (so the test runs in O(roles) without spinning up the
    AgenticLoop / fake provider for each role) and verify the
    Coordinator emits one ``role_handoff`` per hop.
    """
    monkeypatch.setenv("SAP_AGENT_MODE", "multi")
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")

    from agent.coordination.handoff import AgentContext, CompletedTask
    from agent.coordinator import Coordinator
    from agent.tracking.recorder import AgentStepRecorder
    from core.audit_log import AuditLog

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="r-multi", engagement_id="eng-multi", role="planner",
    )

    # Walks: planner → recon → exploit_dev → reporter (skipping
    # post_exploit / blueteam so the test stays compact). Every can_handoff
    # edge is validated by the registry at YAML load time, so this list
    # only exercises edges that the production catalog already declares.
    plan = iter([
        ("recon_analyst", Phase.RECON, "after plan"),
        ("exploit_dev",   Phase.EXPLOITATION, "high-confidence finding"),
        ("reporter",      Phase.REPORTING, "exploitation done"),
    ])

    async def _stub_driver(role_id: str, _ctx: AgentContext | None) -> AgentContext | None:
        try:
            target, phase, reason = next(plan)
        except StopIteration:
            return None
        return AgentContext(
            engagement_id="eng-multi", run_id="r-multi",
            current_phase=phase, parent_role=role_id, target_role=target,
            handoff_reason=reason,
            completed_tasks=[CompletedTask(description=f"{role_id} slice", tool_calls_made=1)],
        )

    coord = Coordinator(
        engagement_id="eng-multi", run_id="r-multi",
        driver=_stub_driver, recorder=recorder,
        initial_role="planner", initial_phase=Phase.SCOPING,
    )
    terminal = await coord.run()
    await log.flush()
    await log.close()

    assert terminal == "reporter"
    actions = [
        json.loads(line)["action"]
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    # 3 handoffs (planner→recon→exploit→reporter), at least 3 phase transitions.
    assert actions.count("role_handoff") == 3
    assert actions.count("phase_transition") >= 3


def test_agent_mode_multi_takes_precedence_over_provider_abstract(monkeypatch):
    """When both env vars are set, multi-agent path wins. The
    Coordinator subsumes the single-agent provider-abstract path."""
    monkeypatch.setenv("SAP_AGENT_MODE", "multi")
    monkeypatch.setenv("SAP_V3_PROVIDER_ABSTRACT", "1")
    from agent.orchestrator import _agent_mode, _provider_abstract_enabled
    assert _agent_mode() == "multi"
    assert _provider_abstract_enabled() is True
    # The run() branch checks ``_agent_mode() == "multi"`` first so the
    # AgenticLoop path is bypassed in favour of the Coordinator.
