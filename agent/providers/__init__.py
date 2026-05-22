"""
agent/providers/ — LLM provider abstraction (Milestone B1).

Public API:

    from agent.providers import (
        LLMProvider, get_provider,
        ChatMessage, ToolSpec, LLMResponse, ParsedToolCall, LLMUsage,
    )

Every concrete provider (Anthropic, OpenAI-compatible — covers cloud OpenAI
+ llama.cpp + LM Studio + Ollama /v1 + vLLM) implements the same surface so
the unified ``AgenticLoop`` (Milestone B2) can pivot at runtime without
touching the orchestrator.

Ollama / vLLM native (non-/v1) providers are stubbed with
``NotImplementedError`` and ship in v3.1.
"""
from __future__ import annotations

from agent.providers.base import LLMProvider
from agent.providers.factory import get_provider, list_providers
from agent.providers.types import (
    ChatMessage,
    LLMResponse,
    LLMUsage,
    ParsedToolCall,
    Role,
    StopReason,
    ToolSpec,
)

__all__ = [
    "LLMProvider",
    "get_provider",
    "list_providers",
    "ChatMessage",
    "ToolSpec",
    "LLMResponse",
    "LLMUsage",
    "ParsedToolCall",
    "Role",
    "StopReason",
]
