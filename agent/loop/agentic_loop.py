"""
agent/loop/agentic_loop.py — Provider-neutral ReAct loop.

Collapses ``Orchestrator._run_anthropic`` (132 LOC) and
``Orchestrator._run_openai`` (167 LOC) into a single iterative driver
parametrized by an :class:`LLMProvider` Strategy. Everything that was
provider-specific (message-shape, tool result formatting, stop-reason
strings) now lives behind the provider interface.

Gated behind ``SAP_V3_PROVIDER_ABSTRACT`` for v3.0.0-rc2: when off, the
orchestrator continues to call its legacy methods so the 530-test legacy
suite stays green. When on, the orchestrator constructs an
:class:`AgenticLoop` and delegates.

The loop deliberately keeps the *chokepoint* policy decisions (scope,
allowlist, sudo) where they always lived — inside ``ToolExecutor`` —
because the security model collapses if anyone short-circuits that.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agent.loop.context import LoopContext
from agent.providers.base import LLMProvider
from agent.providers.types import LLMResponse, ParsedToolCall, StopReason
from agent.tracking.recorder import AgentStepRecorder, _NullRecorder

_log = logging.getLogger(__name__)


class IterationOutcome(StrEnum):
    CONTINUE = "continue"          # produce another iteration
    DONE = "done"                  # model returned text with no tool calls
    ABORTED = "aborted"            # circuit-breaker / budget / timeout / error


@dataclass
class IterationResult:
    outcome: IterationOutcome
    text: str = ""                 # final visible text when outcome=DONE
    reason: str = ""               # human-readable abort reason


# Type alias for the dispatcher the orchestrator hands in. The loop never
# imports ``ToolExecutor`` directly — that keeps the orchestrator free to
# layer the AgentStepRecorder + scope + audit on top.
ToolDispatcher = Callable[[ParsedToolCall], Awaitable[str]]


# Type alias for the optional pre-call mutation hook the orchestrator
# uses to run compaction / budget guard / system-prompt refresh. The
# callable receives the context and may mutate ``ctx.messages`` /
# ``ctx.system``. Returning False from the hook aborts the run gracefully.
PreCallHook = Callable[[LoopContext], Awaitable[bool]]


class AgenticLoop:
    """Single driver for the agentic ReAct loop."""

    def __init__(
        self,
        *,
        provider: LLMProvider,
        dispatcher: ToolDispatcher,
        recorder: AgentStepRecorder | _NullRecorder | None = None,
        pre_call_hook: PreCallHook | None = None,
        on_message: Callable[[str, str], None] | None = None,
        request_timeout: float = 600.0,
        sanitize_for_audit: Callable[[str], str] | None = None,
    ) -> None:
        self._provider = provider
        self._dispatcher = dispatcher
        self._recorder = recorder
        self._pre_call_hook = pre_call_hook
        self._on_message = on_message or (lambda role, text: None)
        self._timeout = request_timeout
        self._sanitize_for_audit = sanitize_for_audit or (lambda s: s)

    # ------------------------------------------------------------------
    # Public driver
    # ------------------------------------------------------------------

    async def run(self, ctx: LoopContext) -> str:
        """Drive the loop until DONE or ABORTED. Returns the final text.

        v3.1 W1.2 — Every iteration is wrapped in
        :meth:`AgentStepRecorder.begin_step` / :meth:`end_step` so the
        BLAKE2b audit chain captures one ``agent_step`` record per ReAct
        cycle. When the recorder is ``_NullRecorder`` (default flag OFF)
        the wrapping calls degrade to no-ops and there is no
        behavioural change for the legacy single-agent path.
        """
        for i in range(ctx.max_iterations):
            ctx.iteration = i
            self._on_message("iteration", str(i + 1))
            if self._recorder is not None:
                try:
                    await self._recorder.begin_step(
                        iteration=i, phase=ctx.phase,
                        state_before={"messages_count": len(ctx.messages)},
                    )
                except Exception:                       # pragma: no cover
                    pass
            if self._pre_call_hook is not None:
                proceed = await self._pre_call_hook(ctx)
                if not proceed:
                    if self._recorder is not None:
                        try:
                            await self._recorder.end_step(
                                state_after={"reason": "pre_call_hook_abort"},
                                error="pre_call_hook returned False",
                            )
                        except Exception:               # pragma: no cover
                            pass
                    return ctx.final_text
            res = await self.run_iteration(ctx)
            if self._recorder is not None:
                try:
                    await self._recorder.end_step(
                        state_after={
                            "outcome": res.outcome.value,
                            "messages_count": len(ctx.messages),
                            "final_text_len": len(ctx.final_text),
                        },
                        error=res.reason if res.outcome is IterationOutcome.ABORTED else "",
                    )
                except Exception:                       # pragma: no cover
                    pass
            if res.outcome is IterationOutcome.DONE:
                ctx.final_text = res.text or ctx.final_text
                return ctx.final_text
            if res.outcome is IterationOutcome.ABORTED:
                return ctx.final_text
            # CONTINUE: next iteration
        # Loop exhausted without DONE/ABORTED.
        return ctx.final_text

    async def run_iteration(self, ctx: LoopContext) -> IterationResult:
        """One think → act → observe pass."""
        # Record the prompt before we send it; the response hash is set
        # post-call. ``include_payload=False`` because the *recorder*
        # decides whether to encrypt-then-store the raw payload. The loop
        # passes only the hash so audit volume stays bounded.
        if self._recorder is not None:
            await self._recorder.record_llm_prompt(
                messages=[m.model_dump() for m in ctx.messages],
                system=ctx.system,
                provider=self._provider.name,
                model=ctx.capabilities_overrides.get("model", "") if ctx.capabilities_overrides else "",
                temperature=ctx.temperature,
                seed=ctx.seed,
                tools_offered=len(ctx.tools),
                include_payload=False,
            )

        # Call provider.
        t0 = time.monotonic()
        try:
            response: LLMResponse = await self._provider.chat(
                system=ctx.system,
                messages=ctx.messages,
                tools=ctx.tools,
                max_tokens=ctx.max_tokens,
                temperature=ctx.temperature,
                seed=ctx.seed,
                timeout=self._timeout,
                capabilities_overrides=ctx.capabilities_overrides,
            )
        except Exception as exc:
            self._on_message(
                "error",
                f"LLM call failed at iteration {ctx.iteration}: "
                f"{type(exc).__name__}: {exc}",
            )
            return IterationResult(outcome=IterationOutcome.ABORTED, reason=str(exc))

        latency_ms = (time.monotonic() - t0) * 1000.0

        if response.stop_reason is StopReason.TIMEOUT:
            self._on_message(
                "error",
                f"LLM call timed out at iteration {ctx.iteration}",
            )
            return IterationResult(outcome=IterationOutcome.ABORTED, reason="timeout")

        # Record the response.
        if self._recorder is not None:
            rh = _stable_hash(response.text + (response.reasoning or "")) if response.text or response.reasoning else ""
            await self._recorder.record_llm_response(
                response_hash_hex=rh,
                provider=self._provider.name,
                model=response.model,
                stop_reason=str(response.stop_reason),
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                latency_ms=latency_ms,
                tool_calls_count=len(response.tool_calls),
                response_payload=None,
            )
            if response.reasoning:
                await self._recorder.record_llm_reasoning(
                    reasoning_text=response.reasoning,
                    reasoning_source=response.reasoning_source or "qwen_think",
                    include_text=False,
                )

        if response.text:
            ctx.final_text = response.text
            ctx.last_thinking = response.reasoning or response.text
            self._on_message("assistant", response.text)

        # No tool calls → terminal.
        if response.stop_reason is StopReason.END_TURN or not response.tool_calls:
            return IterationResult(outcome=IterationOutcome.DONE, text=response.text)

        # Append the assistant message (with native tool_use blocks) so the
        # provider can re-feed it on the next iteration.
        ctx.messages.append(self._provider.format_assistant_message(response))

        # Execute every tool call, gated by the per-tool fuzzy breaker.
        for tc in response.tool_calls:
            self._on_message("tool_call", f"{tc.name}({_safe_json(tc.args)})")
            sig = _fuzzy_signature(tc.name, tc.args)
            ctx.tool_call_counts[sig] += 1
            if ctx.tool_call_counts[sig] > ctx.repetition_limit:
                abort_msg = (
                    f"circuit-breaker: tool '{tc.name}' invoked with identical "
                    f"arguments more than {ctx.repetition_limit} times; aborting loop."
                )
                self._on_message("error", abort_msg)
                ctx.messages.append(self._provider.format_tool_result(
                    call_id=tc.id,
                    tool_name=tc.name,
                    content=_safe_json({"aborted": True, "reason": abort_msg}),
                ))
                return IterationResult(outcome=IterationOutcome.ABORTED, reason=abort_msg)

            try:
                observation = await self._dispatcher(tc)
            except Exception as exc:
                observation = _safe_json({
                    "error": f"{type(exc).__name__}: {exc}",
                    "tool": tc.name,
                })
                self._on_message("error", f"dispatch failed: {tc.name}: {exc}")

            self._on_message("tool_result", _short(observation))

            sanitized = self._sanitize_for_audit(observation)
            ctx.messages.append(self._provider.format_tool_result(
                call_id=tc.id,
                tool_name=tc.name,
                content=sanitized,
            ))

        return IterationResult(outcome=IterationOutcome.CONTINUE)


# ----------------------------------------------------------------------
# Helpers (free functions kept private to the module)
# ----------------------------------------------------------------------


def _fuzzy_signature(tool_name: str, args: dict[str, Any]) -> str:
    """Cheap, deterministic signature for the circuit breaker.

    The legacy orchestrator uses a Jaccard fuzzy match; this simplified
    variant keeps the breaker working in the new loop until the full
    breaker module (extracted in Milestone B4) is wired in. Same semantics
    for the common case of *identical* arg dicts.
    """
    import json as _json
    try:
        canon = _json.dumps(args, sort_keys=True, separators=(",", ":"))
    except Exception:
        canon = repr(args)
    return f"{tool_name}::{canon}"


def _stable_hash(text: str) -> str:
    import hashlib
    return hashlib.blake2b(text.encode("utf-8", errors="replace"), digest_size=32).hexdigest()


def _safe_json(value: Any) -> str:
    import json as _json
    try:
        return _json.dumps(value, ensure_ascii=False)
    except Exception:
        return repr(value)


def _short(text: str, *, limit: int = 4000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"... [+{len(text) - limit} chars]"
