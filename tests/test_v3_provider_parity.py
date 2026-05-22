"""
tests/test_v3_provider_parity.py — Milestone B1+B2 acceptance.

Verifies that the unified ``AgenticLoop`` driving an Anthropic-shaped vs
an OpenAI-shaped provider produces the same DAG of tool calls and the
same final text for an identical set of mocked model responses. This is
the regression guard that gives confidence to flip
``SAP_V3_PROVIDER_ABSTRACT`` from off to on in v3.0.0-rc2.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent.loop import AgenticLoop, LoopContext
from agent.providers.anthropic_provider import AnthropicProvider
from agent.providers.factory import get_provider, list_providers
from agent.providers.openai_provider import OpenAICompatibleProvider
from agent.providers.types import (
    ChatMessage,
    LLMResponse,
    LLMUsage,
    ParsedToolCall,
    Role,
    StopReason,
    ToolSpec,
)


# ── Anthropic SDK mocks (raw shape) ────────────────────────────────────────


class _AnthBlock:
    def __init__(self, **kw: Any) -> None:
        for k, v in kw.items():
            setattr(self, k, v)
    def model_dump(self) -> dict[str, Any]:
        return self.__dict__


class _AnthResponse:
    def __init__(self, content: list[_AnthBlock], stop_reason: str, usage_in: int, usage_out: int) -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = type("U", (), {
            "input_tokens": usage_in,
            "output_tokens": usage_out,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        })()


class _AnthMessagesClient:
    def __init__(self, scripted: list[_AnthResponse]) -> None:
        self._scripted = scripted
        self._i = 0
    def create(self, **kw: Any) -> _AnthResponse:
        resp = self._scripted[self._i]
        self._i += 1
        return resp


class _AnthClient:
    def __init__(self, scripted: list[_AnthResponse]) -> None:
        self.messages = _AnthMessagesClient(scripted)


# ── OpenAI SDK mocks (raw shape) ──────────────────────────────────────────


class _OAIFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _OAIToolCall:
    def __init__(self, id: str, name: str, arguments: str) -> None:
        self.id = id
        self.function = _OAIFunction(name, arguments)


class _OAIMessage:
    def __init__(self, content: str | None, tool_calls: list[_OAIToolCall] | None) -> None:
        self.content = content
        self.tool_calls = tool_calls
        self.reasoning_content = None


class _OAIChoice:
    def __init__(self, msg: _OAIMessage, finish: str) -> None:
        self.message = msg
        self.finish_reason = finish


class _OAIResponse:
    def __init__(self, msg: _OAIMessage, finish: str, usage_in: int, usage_out: int) -> None:
        self.choices = [_OAIChoice(msg, finish)]
        self.usage = type("U", (), {
            "prompt_tokens": usage_in,
            "completion_tokens": usage_out,
        })()


class _OAIChatCompletionsClient:
    def __init__(self, scripted: list[_OAIResponse]) -> None:
        self._scripted = scripted
        self._i = 0
    def create(self, **kw: Any) -> _OAIResponse:
        resp = self._scripted[self._i]
        self._i += 1
        return resp


class _OAIClient:
    def __init__(self, scripted: list[_OAIResponse]) -> None:
        self.chat = type("X", (), {"completions": _OAIChatCompletionsClient(scripted)})()


# ── Tests ──────────────────────────────────────────────────────────────────


def test_factory_lists_anthropic_openai_local():
    names = list_providers()
    assert {"anthropic", "openai", "local"}.issubset(set(names))


def test_factory_raises_on_unknown_provider(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    with pytest.raises(RuntimeError):
        get_provider("definitely-not-a-provider")


def test_anthropic_normalize_tools_uses_input_schema():
    p = AnthropicProvider(client=_AnthClient([]))
    out = p.normalize_tools([
        ToolSpec(name="x", description="d", parameters={"type": "object"})
    ])
    assert out == [{"name": "x", "description": "d", "input_schema": {"type": "object"}}]


def test_openai_normalize_tools_uses_function_wrapper():
    p = OpenAICompatibleProvider(client=_OAIClient([]))
    out = p.normalize_tools([
        ToolSpec(name="x", description="d", parameters={"type": "object"})
    ])
    assert out == [{
        "type": "function",
        "function": {"name": "x", "description": "d", "parameters": {"type": "object"}},
    }]


@pytest.mark.asyncio
async def test_provider_parity_same_dag(monkeypatch):
    """Both providers, when scripted to return the same sequence, must
    produce the same tool DAG and final text under the unified loop."""

    # ── Anthropic script: turn 1 = tool_use(nmap), turn 2 = end_turn text ──
    anth_script = [
        _AnthResponse(
            content=[
                _AnthBlock(type="text", text="Scanning target."),
                _AnthBlock(type="tool_use", id="call_1",
                           name="nmap_scan", input={"host": "10.0.0.1"}),
            ],
            stop_reason="tool_use",
            usage_in=100, usage_out=20,
        ),
        _AnthResponse(
            content=[_AnthBlock(type="text", text="Port 80 open. Done.")],
            stop_reason="end_turn",
            usage_in=120, usage_out=15,
        ),
    ]
    # ── OpenAI script: same shape ────────────────────────────────────────
    import json as _json
    oai_script = [
        _OAIResponse(
            msg=_OAIMessage(
                content="Scanning target.",
                tool_calls=[_OAIToolCall(
                    id="call_1", name="nmap_scan",
                    arguments=_json.dumps({"host": "10.0.0.1"}),
                )],
            ),
            finish="tool_calls",
            usage_in=100, usage_out=20,
        ),
        _OAIResponse(
            msg=_OAIMessage(content="Port 80 open. Done.", tool_calls=None),
            finish="stop",
            usage_in=120, usage_out=15,
        ),
    ]

    anth = AnthropicProvider(client=_AnthClient(anth_script))
    oai = OpenAICompatibleProvider(client=_OAIClient(oai_script))

    dispatched_anth: list[tuple[str, dict[str, Any]]] = []
    dispatched_oai: list[tuple[str, dict[str, Any]]] = []

    async def dispatcher_anth(tc: ParsedToolCall) -> str:
        dispatched_anth.append((tc.name, tc.args))
        return _json.dumps({"open_ports": [80]})

    async def dispatcher_oai(tc: ParsedToolCall) -> str:
        dispatched_oai.append((tc.name, tc.args))
        return _json.dumps({"open_ports": [80]})

    loop_anth = AgenticLoop(provider=anth, dispatcher=dispatcher_anth)
    loop_oai = AgenticLoop(provider=oai, dispatcher=dispatcher_oai)

    ctx_anth = LoopContext(
        run_id="r-anth", engagement_id="e1",
        messages=[ChatMessage(role=Role.USER, content="Scan 10.0.0.1")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=5,
    )
    ctx_oai = LoopContext(
        run_id="r-oai", engagement_id="e1",
        messages=[ChatMessage(role=Role.USER, content="Scan 10.0.0.1")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=5,
    )

    final_anth = await loop_anth.run(ctx_anth)
    final_oai = await loop_oai.run(ctx_oai)

    assert final_anth == "Port 80 open. Done."
    assert final_oai == "Port 80 open. Done."
    assert dispatched_anth == dispatched_oai == [("nmap_scan", {"host": "10.0.0.1"})]


@pytest.mark.asyncio
async def test_circuit_breaker_aborts_on_repeated_tool(monkeypatch):
    """When the same tool with the same args is requested >limit times,
    the loop aborts with a clear reason."""
    # Script: model keeps requesting nmap_scan with identical args; loop
    # should abort once the breaker fires.
    import json as _json
    oai_script = [
        _OAIResponse(
            msg=_OAIMessage(
                content="",
                tool_calls=[_OAIToolCall(
                    id=f"call_{i}", name="nmap_scan",
                    arguments=_json.dumps({"host": "10.0.0.1"}),
                )],
            ),
            finish="tool_calls",
            usage_in=10, usage_out=5,
        )
        for i in range(10)
    ]
    oai = OpenAICompatibleProvider(client=_OAIClient(oai_script))

    async def dispatcher(tc: ParsedToolCall) -> str:
        return _json.dumps({"open_ports": []})

    loop = AgenticLoop(provider=oai, dispatcher=dispatcher)
    ctx = LoopContext(
        run_id="r-breaker", engagement_id="e1",
        messages=[ChatMessage(role=Role.USER, content="loop")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=20,
        repetition_limit=2,
    )
    final = await loop.run(ctx)
    # We never reached a final assistant text; the breaker aborted the run.
    assert ctx.tool_call_counts.most_common(1)[0][1] > ctx.repetition_limit
    # The loop returns whatever ctx.final_text was (likely "" here).
    assert isinstance(final, str)
