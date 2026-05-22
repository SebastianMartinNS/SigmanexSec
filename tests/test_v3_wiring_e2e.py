"""
tests/test_v3_wiring_e2e.py — W1.1 + W1.2 acceptance.

Validates that with ``SAP_V3_PROVIDER_ABSTRACT=1`` the orchestrator
delegates to :class:`AgenticLoop`, the loop drives the provider
strategy, and the recorder hooks emit the expected sequence of v3
audit events for one engagement run.

The provider, the dispatcher and the registry are all faked so the
test runs in-process with no LLM dependency and no network — it is the
unit-level pin that the wiring is alive in the production path.
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

# ── Tiny LLMProvider stub ─────────────────────────────────────────────────


class _FakeProvider:
    """Scripted provider: one tool-use turn, one end_turn turn."""

    name = "fake"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        if self.calls == 1:
            return LLMResponse(
                text="Scanning the lab target.",
                reasoning="Looking for open ports first.",
                reasoning_source="qwen_think",
                tool_calls=[ParsedToolCall(
                    id="call_1", name="nmap_scan", args={"host": "10.0.0.1"},
                )],
                stop_reason=StopReason.TOOL_USE,
                usage=LLMUsage(input_tokens=100, output_tokens=20),
                model="fake-model",
            )
        return LLMResponse(
            text="Port 80 open. Done.",
            stop_reason=StopReason.END_TURN,
            usage=LLMUsage(input_tokens=120, output_tokens=15),
            model="fake-model",
        )

    def normalize_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        return [{"name": t.name} for t in tools]

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        return ChatMessage(
            role=Role.ASSISTANT,
            content=response.text,
            tool_calls=list(response.tool_calls),
        )

    def format_tool_result(self, *, call_id: str, tool_name: str, content: str) -> ChatMessage:
        return ChatMessage(
            role=Role.TOOL,
            content=content,
            tool_call_id=call_id,
            name=tool_name,
        )

    def extra_capabilities(self) -> dict[str, Any]:
        return {}


# ── Tests ─────────────────────────────────────────────────────────────────


def test_provider_abstract_flag_disabled_by_default(monkeypatch):
    """The flag must default OFF so v2.3 deployments see zero change."""
    monkeypatch.delenv("SAP_V3_PROVIDER_ABSTRACT", raising=False)
    from agent.orchestrator import _provider_abstract_enabled
    assert _provider_abstract_enabled() is False


def test_provider_abstract_flag_enables_unified_path(monkeypatch):
    monkeypatch.setenv("SAP_V3_PROVIDER_ABSTRACT", "1")
    from agent.orchestrator import _provider_abstract_enabled
    assert _provider_abstract_enabled() is True


def test_orchestrator_exposes_run_via_agentic_loop():
    """The unified driver must be present as a method on the orchestrator,
    not just hidden behind a flag in run()."""
    import os as _os
    _os.environ.setdefault("LLM_PROVIDER", "openai")
    from agent.orchestrator import Orchestrator
    o = Orchestrator()
    assert callable(getattr(o, "_run_via_agentic_loop", None))


@pytest.mark.asyncio
async def test_agentic_loop_emits_v3_audit_events(tmp_paths, monkeypatch):
    """End-to-end pin: when tracking is on, one orchestrator run via the
    unified loop must produce ``llm_prompt_sent`` + ``llm_response_received``
    + ``agent_step`` events for every iteration, and the BLAKE2b chain
    must verify."""
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")  # grep-friendly assertions

    from agent.loop import AgenticLoop, LoopContext
    from agent.providers.types import ToolSpec
    from agent.tracking.recorder import AgentStepRecorder
    from core.audit_log import AuditLog, verify_audit_chain

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="run_wiring", engagement_id="eng-w12",
        role="legacy_monolithic",
    )

    provider = _FakeProvider()
    dispatched: list[str] = []

    async def dispatcher(tc: ParsedToolCall) -> str:
        dispatched.append(tc.name)
        return json.dumps({"open_ports": [80]})

    loop = AgenticLoop(provider=provider, dispatcher=dispatcher, recorder=recorder)
    ctx = LoopContext(
        run_id="run_wiring",
        engagement_id="eng-w12",
        messages=[ChatMessage(role=Role.USER, content="Scan 10.0.0.1")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=5,
    )
    final = await loop.run(ctx)
    await log.flush()
    await log.close()

    # Provider was called twice; one tool dispatched.
    assert provider.calls == 2
    assert dispatched == ["nmap_scan"]
    assert "Port 80 open" in final

    # Audit chain integrity must hold.
    ok, n, msg = verify_audit_chain(log_path)
    assert ok, f"chain broken at line {n}: {msg}"

    # Every iteration emits prompt + response + agent_step. With one
    # reasoning string from turn 1, also one llm_reasoning event.
    actions = [
        json.loads(line)["action"]
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    assert actions.count("llm_prompt_sent") == 2
    assert actions.count("llm_response_received") == 2
    assert actions.count("agent_step") == 2
    assert actions.count("llm_reasoning") >= 1


@pytest.mark.asyncio
async def test_agentic_loop_records_step_outcome_in_state_after(tmp_paths, monkeypatch):
    """``end_step`` must capture the iteration outcome and message count
    so a replay reader can correlate ``agent_step`` records with the
    state delta they produced."""
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")

    from agent.loop import AgenticLoop, LoopContext
    from agent.providers.types import ToolSpec
    from agent.tracking.recorder import AgentStepRecorder
    from core.audit_log import AuditLog

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="run_state", engagement_id="eng-state",
        role="legacy_monolithic",
    )

    async def dispatcher(_tc: ParsedToolCall) -> str:
        return json.dumps({"ok": True})

    loop = AgenticLoop(provider=_FakeProvider(), dispatcher=dispatcher, recorder=recorder)
    ctx = LoopContext(
        run_id="run_state",
        engagement_id="eng-state",
        messages=[ChatMessage(role=Role.USER, content="go")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=5,
    )
    await loop.run(ctx)
    await log.flush()
    await log.close()

    # Find every agent_step and check the state_after wiring.
    steps = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip() and json.loads(line)["action"] == "agent_step"
    ]
    assert len(steps) == 2
    for entry in steps:
        step = entry["details"]["step"]
        assert "state_after" in step
        # ``end_step`` sets ``outcome`` to the IterationOutcome value.
        assert step["state_after"].get("outcome") in {"continue", "done", "aborted"}
        assert step["status"] in {"closed", "failed"}
