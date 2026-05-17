"""LLM-driven message summarizer.

When the projected context exceeds the configured budget, the oldest
non-summarized messages are condensed into a single ``system`` block
that replaces them in the active prompt window. The originals stay in
the recall store so the agent can still ``recall_search`` them.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

SummaryFn = Callable[[str], Awaitable[str]]

DEFAULT_PROMPT = (
    "You are a memory compactor. Summarize the following conversation excerpt "
    "into <=400 words of dense bullet points. Preserve: discovered hosts/ports, "
    "credentials, exploited vulnerabilities, decisions taken, and any pending "
    "TODOs. Drop pleasantries and repeated tool I/O. Output plain text only.\n\n"
)


def format_messages_for_summary(messages: list[dict]) -> str:
    parts: list[str] = []
    for m in messages:
        role = m.get("role", "?")
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(str(b.get("content", b.get("text", ""))) for b in content)
        tool = m.get("tool_name") or ""
        prefix = f"[{role}{':' + tool if tool else ''}]"
        parts.append(f"{prefix} {content}")
    return "\n".join(parts)


async def summarize(
    messages: list[dict],
    summary_fn: SummaryFn | None = None,
    *,
    prompt: str = DEFAULT_PROMPT,
) -> str:
    """Compact *messages* into a single string.

    If *summary_fn* is None, falls back to a deterministic head/tail
    extract (no LLM call) — keeps the system functional even when the
    LLM is unreachable, at the cost of summary quality.
    """
    if not messages:
        return ""
    formatted = format_messages_for_summary(messages)
    if summary_fn is None:
        return _fallback_summary(formatted)
    try:
        out = await summary_fn(prompt + formatted)
        return out.strip() or _fallback_summary(formatted)
    except Exception:
        return _fallback_summary(formatted)


def _fallback_summary(text: str, head: int = 800, tail: int = 800) -> str:
    if len(text) <= head + tail + 200:
        return text
    return (
        text[:head]
        + f"\n\n[... {len(text) - head - tail} chars elided ...]\n\n"
        + text[-tail:]
    )


def run_sync(coro):
    """Helper for tests — run an async summary in a fresh loop."""
    return asyncio.run(coro)
