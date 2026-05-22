"""
agent/budget/token_budget.py — Pre-flight prompt token budget.

Extracted from ``agent/orchestrator.py`` (formerly ``_measure_prompt``
and ``_prompt_budget_guard``) so the budget logic can be unit-tested
without spinning up a full Orchestrator instance.

Behaviour is preserved bit-for-bit: a thin delegate in
``Orchestrator._measure_prompt`` / ``_prompt_budget_guard`` calls into
these functions, so every legacy caller and every legacy test sees the
same return values.

ROOT-CAUSE context (2026-04-30): without this guard, the orchestrator
posts >n_ctx prompts to llama-server, which now returns HTTP 400 instead
of silently truncating. The guard truncates the longest in-prompt tool
result first; if still over budget, it returns ``overflow=True`` so the
caller aborts the iteration before the network call.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def measure_prompt(
    messages: list[Any],
    *,
    system_text: str = "",
    tools: list[Any] | None = None,
) -> int:
    """Approximate total prompt tokens for the next LLM call.

    Mirrors what the server tokenises: the system header, the message
    history (Anthropic blocks + OpenAI dicts both honoured by
    ``count_message_tokens``) and the tool schemas. Returns 0 when the
    optional memory deps are not installed.
    """
    try:
        from core.memory.tokens import count_message_tokens, count_tokens
    except Exception:
        return 0
    total = count_message_tokens(messages or [])
    if system_text:
        total += count_tokens(system_text)
    if tools:
        try:
            total += count_tokens(json.dumps(tools, default=str))
        except Exception:
            for t in tools:
                if isinstance(t, dict):
                    total += count_tokens(str(t.get("name", "")))
                    total += count_tokens(str(t.get("description", "")))
    return total


def prompt_budget_guard(
    messages: list[Any],
    *,
    system_text: str = "",
    tools: list[Any] | None = None,
    iteration: int = 0,
    budget: int,
    warn_threshold: int,
    callback_result_cap: int,
    truncator: Callable[[str], str],
    on_event: Callable[[str, str], None] | None = None,
) -> tuple[list[Any], bool]:
    """Guard the next LLM call against the prompt token budget.

    Returns ``(maybe_pruned_messages, overflow)``. When ``overflow`` is
    True the caller must abort the iteration because even after pruning
    the prompt would exceed ``budget``.

    Parameters
    ----------
    budget
        Hard ceiling, matches ``SAP_PROMPT_TOKEN_BUDGET``.
    warn_threshold
        Soft ceiling that fires an observability event without aborting.
        ``warn_threshold <= 0`` disables the event.
    callback_result_cap
        Lower bound on tool-result truncation length (matches
        ``SAP_CALLBACK_RESULT_CAP``).
    truncator
        Callable used to shrink a single oversized string. The caller
        supplies its own (the orchestrator's ``_truncate_for_callback``)
        so the smart head+tail behaviour stays in one place.
    on_event
        Optional callback used to emit observability events. Receives
        ``(channel, message)`` like the orchestrator's ``_on_message``.
    """
    def _emit(channel: str, msg: str) -> None:
        if on_event is None:
            return
        try:
            on_event(channel, msg)
        except Exception:
            pass

    total = measure_prompt(messages, system_text=system_text, tools=tools)
    if warn_threshold > 0 and total >= warn_threshold:
        _emit("token_budget", f"iter={iteration} tokens={total}/{budget}")
    if total <= budget:
        return messages, False

    pruned = list(messages)
    max_passes = 8
    cap = max(2048, callback_result_cap)
    for _pass in range(max_passes):
        longest_idx: int | tuple[int, int] = -1
        longest_len = 0
        for i, m in enumerate(pruned):
            content = m.get("content") if isinstance(m, dict) else None
            if isinstance(content, str):
                if len(content) > longest_len:
                    longest_len, longest_idx = len(content), i
            elif isinstance(content, list):
                for j, blk in enumerate(content):
                    if isinstance(blk, dict):
                        txt = blk.get("content") or blk.get("text")
                        if isinstance(txt, str) and len(txt) > longest_len:
                            longest_len, longest_idx = len(txt), (i, j)
        if longest_idx == -1 or longest_len <= cap:
            break
        if isinstance(longest_idx, tuple):
            i, j = longest_idx
            blk = pruned[i]["content"][j]
            key = "content" if "content" in blk else "text"
            blk[key] = truncator(blk[key])
        else:
            m = pruned[longest_idx]
            pruned[longest_idx] = {**m, "content": truncator(m["content"])}
        new_total = measure_prompt(pruned, system_text=system_text, tools=tools)
        _emit("token_budget", f"iter={iteration} pruned tokens={new_total}/{budget}")
        if new_total <= budget:
            return pruned, False
        total = new_total

    _emit(
        "error",
        f"prompt budget overflow after pruning: {total}>{budget} "
        f"at iter {iteration}; aborting to avoid HTTP 400 from llama-server.",
    )
    return pruned, True
