"""
agent/providers/types.py — Provider-neutral types.

These models normalize what the orchestrator passes *to* a provider and what
the provider passes *back*. The wire format on each end (Anthropic blocks
vs OpenAI deltas) is each provider's private business — by the time data
reaches :class:`AgenticLoop` it is in these shapes.

Why Pydantic and not plain dataclasses
--------------------------------------

The audit recorder (Milestone A) serializes provider input/output into the
BLAKE2b chain. Pydantic gives us ``model_dump(mode='json')`` with consistent
key ordering for stable ``prompt_hash`` computation across runs.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class StopReason(StrEnum):
    END_TURN = "end_turn"           # model decided it had nothing more to say
    TOOL_USE = "tool_use"           # model requested a tool call
    MAX_TOKENS = "max_tokens"       # output cap hit
    TIMEOUT = "timeout"             # client-side timeout
    ERROR = "error"                 # exception during the call
    OTHER = "other"                 # provider-specific stop reason


class ChatMessage(BaseModel):
    """One turn in the conversation.

    ``content`` is the visible text. ``tool_calls`` is set on assistant
    messages that requested tool execution. ``tool_call_id`` and ``name``
    are set on tool-result messages (role=tool).

    Providers may carry *extra* shape (e.g. Anthropic structured content
    blocks) inside ``raw`` for round-trip fidelity, but the orchestrator
    only reads the normalized fields.
    """

    role: Role
    content: str = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    tool_call_id: str = ""
    name: str = ""                                 # tool name for tool-role
    raw: dict[str, Any] | None = None              # provider-native payload


class ToolSpec(BaseModel):
    """Tool description shared across providers.

    ``parameters`` follows the JSON-Schema-2020-12 subset accepted by both
    Anthropic and OpenAI. Provider adapters translate this to the
    provider-specific shape (e.g. wrapping under ``{"type":"function"}``).
    """

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ParsedToolCall(BaseModel):
    """A tool invocation requested by the model."""

    id: str
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


class LLMUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


class LLMResponse(BaseModel):
    """Normalized output of one ``LLMProvider.chat`` call."""

    text: str = ""
    reasoning: str = ""                            # CoT / thinking, if exposed
    reasoning_source: Literal[
        "",
        "qwen_think",
        "openai_reasoning",
        "anthropic_thinking",
    ] = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    stop_reason: StopReason = StopReason.OTHER
    usage: LLMUsage = Field(default_factory=LLMUsage)
    model: str = ""
    raw: dict[str, Any] | None = None              # for replay fidelity


ChatMessage.model_rebuild()
