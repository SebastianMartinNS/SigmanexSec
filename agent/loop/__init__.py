"""
agent/loop/ — Provider-neutral agentic loop (Milestone B2).

Composes :class:`LLMProvider` (Milestone B1) with the existing security
chokepoints (scope_validator, executor.run, audit_log) to give the
orchestrator a single ``run_iteration`` method instead of the two
provider-specific ``_run_anthropic`` / ``_run_openai`` clones.

The loop is gated behind ``SAP_V3_PROVIDER_ABSTRACT``; when off, the
orchestrator continues to call its legacy ``_run_anthropic`` /
``_run_openai`` methods so the 530-test legacy suite stays green.

Public API:

    from agent.loop import AgenticLoop, LoopContext, IterationResult
"""
from __future__ import annotations

from agent.loop.agentic_loop import AgenticLoop, IterationOutcome, IterationResult
from agent.loop.context import LoopContext

__all__ = [
    "AgenticLoop",
    "IterationResult",
    "IterationOutcome",
    "LoopContext",
]
