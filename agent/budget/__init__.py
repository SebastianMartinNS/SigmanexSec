"""
agent/budget/ — Pre-flight token budget + fuzzy circuit-breaker.

Both submodules are pure functions / small classes with no orchestrator
dependency, so unit tests can exercise them in isolation. Each is
imported back into ``agent/orchestrator.py`` via thin delegate methods
to preserve the legacy public surface (``self._measure_prompt``,
``self._fuzzy_signature``) for the 530-test legacy suite.
"""
from __future__ import annotations

from agent.budget.breaker import (
    FuzzyBreaker,
    canonicalise_url,
    tool_call_signature,
    tool_call_token_set,
)
from agent.budget.token_budget import (
    measure_prompt,
    prompt_budget_guard,
)

__all__ = [
    "measure_prompt",
    "prompt_budget_guard",
    "FuzzyBreaker",
    "tool_call_signature",
    "tool_call_token_set",
    "canonicalise_url",
]
