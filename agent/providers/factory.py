"""
agent/providers/factory.py — Provider lookup.

Replaces the historical ``if _PROVIDER == "anthropic"`` / ``elif _PROVIDER
in ("openai", "local")`` block at ``agent/orchestrator.py:115-134``.

Resolution rules (mirrors the previous behaviour exactly so v3.0.0-rc2
flips no observable knob):

* ``anthropic`` → :class:`AnthropicProvider`.
* ``openai``   → :class:`OpenAICompatibleProvider` with cloud defaults.
* ``local``    → :class:`OpenAICompatibleProvider` with
                 ``base_url = LOCAL_BASE_URL`` (default
                 ``http://localhost:8080/v1``).
* ``ollama``, ``vllm``, ``llama_cpp``: stubbed via
  :func:`_stub_provider_for_ollama_or_vllm` (v3.1).
"""
from __future__ import annotations

import os

from agent.providers.base import LLMProvider


def list_providers() -> list[str]:
    """Names supported by :func:`get_provider`. Stable for v3.0.0."""
    return ["anthropic", "openai", "local"]


def get_provider(name: str | None = None) -> LLMProvider:
    """Return a provider instance for *name*.

    *name* defaults to ``$LLM_PROVIDER`` (the env var the legacy loop
    used). Raises ``RuntimeError`` on unknown names — same surface as the
    legacy ``elif`` chain.
    """
    if name is None:
        name = os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()
    else:
        name = name.strip().lower()

    if name == "anthropic":
        from agent.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    if name == "openai":
        from agent.providers.openai_provider import OpenAICompatibleProvider
        return OpenAICompatibleProvider()
    if name == "local":
        from agent.providers.openai_provider import OpenAICompatibleProvider
        base = os.environ.get("LOCAL_BASE_URL", "http://localhost:8080/v1")
        return OpenAICompatibleProvider(base_url=base)
    if name in ("ollama", "vllm", "llama_cpp"):
        from agent.providers.openai_provider import _stub_provider_for_ollama_or_vllm
        return _stub_provider_for_ollama_or_vllm(name)
    raise RuntimeError(f"Unsupported LLM_PROVIDER: {name!r}")
