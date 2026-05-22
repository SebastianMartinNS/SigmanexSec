"""
agent/loop/context.py — Per-iteration loop state.

A small mutable carrier so :class:`AgenticLoop.run_iteration` does not
have to take a dozen positional arguments. Instances are owned by the
``AgenticLoop`` instance and threaded through helpers (budget guard,
breaker, recorder) without being globally accessible.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from agent.providers.types import ChatMessage, ToolSpec
from core.models import Phase


@dataclass
class LoopContext:
    """All state needed to drive one orchestrator run.

    Owned by the loop; producers (orchestrator) build it once at the
    start of :meth:`AgenticLoop.run` and pass the same instance to every
    ``run_iteration`` call.

    Mutable on purpose: ``messages`` grows turn by turn, ``iteration``
    counts up, the breaker accumulates fuzzy-signature hits. The frozen
    pieces (provider, system prompt, tools) live next to it.
    """

    # Identity ─────────────────────────────────────────────────────────────
    run_id: str
    engagement_id: str = "-"
    role: str = "legacy_monolithic"
    phase: Phase = Phase.SCANNING

    # Conversation state ───────────────────────────────────────────────────
    system: str = ""
    messages: list[ChatMessage] = field(default_factory=list)
    tools: list[ToolSpec] = field(default_factory=list)

    # Run-level knobs ──────────────────────────────────────────────────────
    max_tokens: int = 8096
    temperature: float = 0.0
    seed: int | None = None
    iteration: int = 0
    max_iterations: int = 50

    # Breaker ──────────────────────────────────────────────────────────────
    tool_call_counts: Counter = field(default_factory=Counter)
    repetition_limit: int = 3

    # Output collected so far ──────────────────────────────────────────────
    final_text: str = ""
    last_thinking: str = ""

    # Capabilities the producer wants forwarded to the provider on every
    # call (Anthropic ``thinking`` blocks, llama.cpp ``cache_prompt``, ...).
    capabilities_overrides: dict | None = None
