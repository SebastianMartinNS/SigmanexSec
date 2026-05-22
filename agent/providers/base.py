"""
agent/providers/base.py — LLMProvider Protocol.

Concrete providers expose this surface and *only* this surface to the loop.
Anything provider-specific (Anthropic ``thinking`` blocks, llama.cpp
``cache_prompt``) lives in :meth:`LLMProvider.extra_capabilities` and is
consumed via ``capabilities_overrides`` on :meth:`chat`.

Every method is documented with the contract the unified loop relies on.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from agent.providers.types import ChatMessage, LLMResponse, ToolSpec


@runtime_checkable
class LLMProvider(Protocol):
    """Provider Strategy contract.

    Implementations live in sibling modules (``anthropic_provider``,
    ``openai_provider``, ...) and are registered with the factory.

    Provider implementations are *thread-safe but not reentrant on a single
    client*: the unified loop never invokes two ``chat`` calls in parallel
    on the same provider instance.
    """

    name: str
    """Stable identifier for audit + factory lookup. Lowercase, no spaces."""

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
        """Run one completion turn.

        Contract:
        * Returns within ``timeout`` seconds or raises ``TimeoutError``.
        * Never mutates ``messages`` / ``tools``.
        * Never logs prompt content (the recorder owns that).
        * If the provider does not support an option (``seed`` on Anthropic
          today, ``cache_prompt`` on cloud OpenAI), it silently ignores it
          rather than raising — this is a permissive Strategy.
        """
        ...

    def normalize_tools(self, tools: list[ToolSpec]) -> Any:
        """Translate ``ToolSpec`` list into the provider-native shape.

        Returned value is opaque to the loop. The loop only ever passes it
        back into :meth:`chat`.
        """
        ...

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        """Turn a response into an assistant ChatMessage suitable to append
        back into ``messages`` for the next iteration."""
        ...

    def format_tool_result(
        self,
        *,
        call_id: str,
        tool_name: str,
        content: str,
    ) -> ChatMessage:
        """Build the tool-result message to feed back to the model.

        Returns a ``ChatMessage`` with the right role / fields for the
        provider's wire format. (Anthropic uses ``role=user`` carrying a
        ``tool_result`` block; OpenAI uses ``role=tool`` with ``tool_call_id``.)
        """
        ...

    def extra_capabilities(self) -> dict[str, Any]:
        """Provider-native knobs surfaced to the loop or to advanced callers.

        Returned dict keys are stable strings (e.g. ``"thinking"``,
        ``"cache_prompt"``). Values are JSON-serializable. The loop does not
        interpret them; it forwards through ``capabilities_overrides``.
        """
        ...
