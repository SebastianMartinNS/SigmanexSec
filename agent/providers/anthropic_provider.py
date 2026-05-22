"""
agent/providers/anthropic_provider.py — Anthropic Messages API adapter.

Wraps the official ``anthropic`` SDK client behind :class:`LLMProvider`. The
loop never reaches the SDK directly after Milestone B2 lands; only this
file (and the audit recorder, which sees the normalized shape) touches it.
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


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API provider."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        default_model: str | None = None,
        client: Any | None = None,
        request_timeout: float = 600.0,
    ) -> None:
        if client is not None:
            self._client = client
        else:
            import anthropic
            self._client = anthropic.Anthropic(
                api_key=api_key or os.environ.get("ANTHROPIC_API_KEY", ""),
                timeout=request_timeout,
            )
        self._default_model = default_model or os.environ.get(
            "LLM_MODEL", "claude-opus-4-7",
        )

    # ------------------------------------------------------------------
    # LLMProvider surface
    # ------------------------------------------------------------------

    def normalize_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters or {"type": "object", "properties": {}},
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
        seed: int | None = None,           # Anthropic ignores explicit seed today
        timeout: float = 60.0,
        capabilities_overrides: dict[str, Any] | None = None,
    ) -> LLMResponse:
        anthropic_tools = self.normalize_tools(tools)
        anthropic_messages = self._to_anthropic_messages(messages)
        model = (capabilities_overrides or {}).get("model") or self._default_model
        extra: dict[str, Any] = {}
        # ``thinking`` blocks are a paid feature gated on the API tier; allow
        # advanced callers to surface them via the capabilities pipe.
        if capabilities_overrides:
            for k in ("thinking", "top_k", "top_p"):
                if k in capabilities_overrides:
                    extra[k] = capabilities_overrides[k]
        try:
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self._client.messages.create,
                    model=model,
                    system=system,
                    tools=anthropic_tools,
                    messages=anthropic_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **extra,
                ),
                timeout=timeout,
            )
        except TimeoutError:
            return LLMResponse(
                stop_reason=StopReason.TIMEOUT,
                model=model,
                reasoning_source="anthropic_thinking",
            )
        return self._from_anthropic_response(response, model=model)

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        # When we're going to hand the assistant turn back to Anthropic in
        # the next iteration, we must preserve the original block list so
        # the API sees ``tool_use`` blocks paired with subsequent
        # ``tool_result`` blocks. The raw payload is the source of truth.
        if response.raw and "content" in response.raw:
            return ChatMessage(
                role=Role.ASSISTANT,
                content=response.text,
                tool_calls=list(response.tool_calls),
                raw={"content": response.raw["content"]},
            )
        return ChatMessage(
            role=Role.ASSISTANT,
            content=response.text,
            tool_calls=list(response.tool_calls),
        )

    def format_tool_result(
        self,
        *,
        call_id: str,
        tool_name: str,
        content: str,
    ) -> ChatMessage:
        # Anthropic ships tool results inside a user-role message that
        # carries a list of ``tool_result`` blocks.
        return ChatMessage(
            role=Role.USER,
            content="",
            tool_call_id=call_id,
            name=tool_name,
            raw={
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": call_id,
                        "content": content,
                    }
                ]
            },
        )

    def extra_capabilities(self) -> dict[str, Any]:
        return {
            "thinking": "block",            # opt-in via capabilities_overrides
            "cache_prompt": False,          # not supported
            "seed": False,                  # not supported (ignored)
            "structured_outputs": False,
            "tool_use_blocks": True,
        }

    # ------------------------------------------------------------------
    # Translation helpers (private)
    # ------------------------------------------------------------------

    def _to_anthropic_messages(self, messages: list[ChatMessage]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for m in messages:
            if m.raw and "content" in m.raw:
                # Caller already speaks Anthropic — pass through verbatim.
                out.append({"role": str(m.role), "content": m.raw["content"]})
                continue
            if m.role == Role.SYSTEM:
                # System message must be passed as the ``system=`` kwarg,
                # not inline. Defensive skip if it leaked in.
                continue
            if m.role == Role.ASSISTANT and m.tool_calls:
                content: list[dict[str, Any]] = []
                if m.content:
                    content.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.args,
                    })
                out.append({"role": "assistant", "content": content})
                continue
            if m.role == Role.TOOL:
                out.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": m.tool_call_id,
                            "content": m.content,
                        }
                    ],
                })
                continue
            out.append({"role": str(m.role), "content": m.content})
        return out

    def _from_anthropic_response(self, response: Any, *, model: str) -> LLMResponse:
        text_parts: list[str] = []
        tool_calls: list[ParsedToolCall] = []
        thinking_parts: list[str] = []
        content_blocks: list[Any] = []

        for block in getattr(response, "content", []) or []:
            content_blocks.append(_block_as_dict(block))
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                args = getattr(block, "input", {}) or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                tool_calls.append(ParsedToolCall(
                    id=getattr(block, "id", ""),
                    name=getattr(block, "name", ""),
                    args=args if isinstance(args, dict) else {},
                ))
            elif btype == "thinking":
                thinking_parts.append(getattr(block, "thinking", "") or "")

        usage_obj = getattr(response, "usage", None)
        usage = LLMUsage(
            input_tokens=int(getattr(usage_obj, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage_obj, "output_tokens", 0) or 0),
            cache_read_input_tokens=int(
                getattr(usage_obj, "cache_read_input_tokens", 0) or 0
            ),
            cache_creation_input_tokens=int(
                getattr(usage_obj, "cache_creation_input_tokens", 0) or 0
            ),
        )
        sr = getattr(response, "stop_reason", "") or ""
        stop = {
            "end_turn":  StopReason.END_TURN,
            "tool_use":  StopReason.TOOL_USE,
            "max_tokens": StopReason.MAX_TOKENS,
        }.get(sr, StopReason.OTHER)
        return LLMResponse(
            text="\n".join(text_parts).strip(),
            reasoning="\n".join(thinking_parts).strip(),
            reasoning_source="anthropic_thinking" if thinking_parts else "",
            tool_calls=tool_calls,
            stop_reason=stop,
            usage=usage,
            model=model,
            raw={"content": content_blocks, "stop_reason": sr},
        )


def _block_as_dict(block: Any) -> Any:
    """Coerce an Anthropic content block to a JSON-serializable dict.

    The SDK ships Pydantic models; ``model_dump()`` is the canonical path
    when available, with a defensive ``getattr`` fallback for stub objects
    used in tests.
    """
    if hasattr(block, "model_dump"):
        try:
            return block.model_dump()
        except Exception:  # pragma: no cover
            pass
    out: dict[str, Any] = {}
    for key in ("type", "text", "id", "name", "input", "tool_use_id", "thinking"):
        if hasattr(block, key):
            out[key] = getattr(block, key)
    return out
