"""
agent/providers/openai_provider.py — OpenAI Chat Completions API adapter.

Covers cloud OpenAI **and** every OpenAI-compatible local backend the
project ships against (llama.cpp ``--api``, LM Studio, Ollama ``/v1``,
vLLM, KoboldCPP). The differences are entirely on the network side: the
base URL and the model string.

Provider-specific tweaks (Qwen3 ``<think>`` parsing, llama.cpp
``cache_prompt``) are forwarded through ``capabilities_overrides`` so the
loop stays neutral.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

from agent.providers.base import LLMProvider
from agent.providers.types import (
    ChatMessage,
    LLMResponse,
    LLMUsage,
    ParsedToolCall,
    Role,
    StopReason,
    ToolSpec,
)


def _strip_thinking(text: str) -> tuple[str, str]:
    """Qwen3 ``<think>…</think>`` separator.

    Mirrors :func:`agent.orchestrator._strip_thinking` exactly so swap-in
    parity is preserved.
    """
    import re
    thinking_parts = re.findall(r"<think>(.*?)</think>", text, re.DOTALL)
    visible = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    return visible, "\n".join(thinking_parts).strip()


class OpenAICompatibleProvider(LLMProvider):
    """OpenAI Chat Completions provider (cloud + every local OpenAI-/v1/ server)."""

    name = "openai"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        default_model: str | None = None,
        client: Any | None = None,
        request_timeout: float = 600.0,
        cache_prompt: bool = True,
    ) -> None:
        self._cache_prompt = cache_prompt
        if client is not None:
            self._client = client
        else:
            import openai as _openai_lib
            self._openai_lib = _openai_lib
            self._client = _openai_lib.OpenAI(
                base_url=base_url,
                api_key=api_key or os.environ.get(
                    "OPENAI_API_KEY", os.environ.get("LOCAL_LLM_API_KEY", "local"),
                ),
                timeout=request_timeout,
            )
            self._NOT_GIVEN = _openai_lib.NOT_GIVEN
        # Lazy import safety: if a stub client is injected (tests),
        # provide a benign sentinel so the optional-tools branch works.
        if not hasattr(self, "_NOT_GIVEN"):
            try:
                import openai as _openai_lib  # type: ignore[import-not-found]
                self._NOT_GIVEN = _openai_lib.NOT_GIVEN
            except ImportError:                       # pragma: no cover
                self._NOT_GIVEN = None
        self._default_model = default_model or os.environ.get(
            "LLM_MODEL", "gpt-4o-mini",
        )

    # ------------------------------------------------------------------
    # LLMProvider surface
    # ------------------------------------------------------------------

    def normalize_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters or {"type": "object", "properties": {}},
                },
            }
            for t in tools
        ]

    async def chat(
        self,
        *,
        system: str,
        messages: list[ChatMessage],
        tools: list[ToolSpec],
        max_tokens: int,
        temperature: float = 0.0,
        seed: int | None = None,
        timeout: float = 60.0,
        capabilities_overrides: dict[str, Any] | None = None,
    ) -> LLMResponse:
        oai_tools = self.normalize_tools(tools) if tools else None
        oai_messages = self._to_openai_messages(system, messages)
        model = (capabilities_overrides or {}).get("model") or self._default_model
        extra_body: dict[str, Any] = {}
        if self._cache_prompt:
            # llama.cpp /v1 honours ``cache_prompt``; cloud OpenAI ignores it.
            extra_body["cache_prompt"] = True
        if capabilities_overrides:
            extra_body.update(capabilities_overrides.get("extra_body", {}))

        kwargs: dict[str, Any] = {
            "model": model,
            "messages": oai_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "extra_body": extra_body,
        }
        if seed is not None:
            kwargs["seed"] = seed
        if oai_tools:
            kwargs["tools"] = oai_tools
            kwargs["tool_choice"] = "auto"
        elif self._NOT_GIVEN is not None:
            kwargs["tools"] = self._NOT_GIVEN
            kwargs["tool_choice"] = self._NOT_GIVEN

        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._client.chat.completions.create, **kwargs,
                ),
                timeout=timeout,
            )
        except TimeoutError:
            return LLMResponse(
                stop_reason=StopReason.TIMEOUT,
                model=model,
                reasoning_source="qwen_think",
            )
        return self._from_openai_response(response, model=model)

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        return ChatMessage(
            role=Role.ASSISTANT,
            content=response.text,
            tool_calls=list(response.tool_calls),
            raw=(response.raw or {}).get("assistant_message"),
        )

    def format_tool_result(
        self,
        *,
        call_id: str,
        tool_name: str,
        content: str,
    ) -> ChatMessage:
        return ChatMessage(
            role=Role.TOOL,
            content=content,
            tool_call_id=call_id,
            name=tool_name,
        )

    def extra_capabilities(self) -> dict[str, Any]:
        return {
            "cache_prompt": self._cache_prompt,
            "thinking": "qwen_think",
            "seed": True,
            "structured_outputs": True,
            "extra_body_passthrough": True,
        }

    # ------------------------------------------------------------------
    # Translation helpers (private)
    # ------------------------------------------------------------------

    def _to_openai_messages(self, system: str, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})
        for m in messages:
            if m.role == Role.SYSTEM:
                # Allow caller-side system; merge by overwriting the leading
                # system header if present.
                if out and out[0].get("role") == "system":
                    out[0]["content"] = m.content
                else:
                    out.insert(0, {"role": "system", "content": m.content})
                continue
            if m.raw:
                out.append(m.raw)
                continue
            if m.role == Role.ASSISTANT and m.tool_calls:
                out.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.args, ensure_ascii=False),
                            },
                        }
                        for tc in m.tool_calls
                    ],
                })
                continue
            if m.role == Role.TOOL:
                out.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id,
                    "content": m.content,
                })
                continue
            out.append({"role": str(m.role), "content": m.content})
        return out

    def _from_openai_response(self, response: Any, *, model: str) -> LLMResponse:
        choice = response.choices[0]
        msg = choice.message
        raw_content = msg.content or ""
        # llama.cpp jinja exposes reasoning out-of-band; legacy backends
        # inline ``<think>…</think>``. Handle both.
        reasoning_attr = getattr(msg, "reasoning_content", None) or ""
        visible, inline_think = _strip_thinking(raw_content)
        reasoning = (reasoning_attr + "\n" + inline_think).strip()
        reasoning_source = "qwen_think" if reasoning else ""

        tool_calls: list[ParsedToolCall] = []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments)
            except (json.JSONDecodeError, AttributeError):
                args = {}
            tool_calls.append(ParsedToolCall(
                id=tc.id,
                name=tc.function.name,
                args=args if isinstance(args, dict) else {},
            ))

        usage_obj = getattr(response, "usage", None)
        usage = LLMUsage(
            input_tokens=int(getattr(usage_obj, "prompt_tokens", 0) or 0),
            output_tokens=int(getattr(usage_obj, "completion_tokens", 0) or 0),
        )
        sr = getattr(choice, "finish_reason", "") or ""
        stop = {
            "stop":       StopReason.END_TURN,
            "length":     StopReason.MAX_TOKENS,
            "tool_calls": StopReason.TOOL_USE,
        }.get(sr, StopReason.OTHER)
        # Preserve the raw assistant message dict so format_assistant_message
        # can echo CoT text back to llama.cpp's prefix cache on re-feed.
        raw_assistant = {
            "role": "assistant",
            "content": raw_content or None,
        }
        if tool_calls:
            raw_assistant["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.args, ensure_ascii=False),
                    },
                }
                for tc in tool_calls
            ]
        return LLMResponse(
            text=visible,
            reasoning=reasoning,
            reasoning_source=reasoning_source,
            tool_calls=tool_calls,
            stop_reason=stop,
            usage=usage,
            model=model,
            raw={"assistant_message": raw_assistant, "finish_reason": sr},
        )


def _stub_provider_for_ollama_or_vllm(name: str) -> LLMProvider:
    """v3.1 native adapters land here. v3.0.0 forwards to OpenAI-compatible."""
    raise NotImplementedError(
        f"Native '{name}' provider lands in v3.1. v3.0.0 supports it via "
        f"the OpenAI-compatible /v1 endpoint — set LLM_PROVIDER=local and "
        f"point LOCAL_BASE_URL at your {name} server."
    )
