"""Token counting with graceful fallback when tiktoken is unavailable."""
from __future__ import annotations

from functools import lru_cache

try:
    import tiktoken  # type: ignore

    _HAVE_TIKTOKEN = True
except ImportError:  # pragma: no cover
    _HAVE_TIKTOKEN = False


@lru_cache(maxsize=1)
def _encoder():
    if not _HAVE_TIKTOKEN:
        return None
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:  # pragma: no cover
        return None


def count_tokens(text: str) -> int:
    """Return an approximate token count for *text*.

    Uses the ``cl100k_base`` BPE encoder when ``tiktoken`` is available;
    otherwise falls back to a 4-chars-per-token heuristic, which is within
    ~10% of the true count for both Latin scripts and Qwen3's tokenizer.
    """
    if not text:
        return 0
    enc = _encoder()
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:  # pragma: no cover
            pass
    return max(1, len(text) // 4)


def _count_block_tokens(block) -> int:
    """Token cost of a single content block.

    Handles three shapes the orchestrator actually feeds us:
      - OpenAI-style ``dict`` blocks: ``{"text": ...}`` / ``{"content": ...}``.
      - Anthropic SDK objects (``TextBlock``, ``ToolUseBlock``,
        ``ToolResultBlock``): not dicts, must use ``getattr``.
      - Bare strings (rare).
    """
    if block is None:
        return 0
    if isinstance(block, str):
        return count_tokens(block)
    if isinstance(block, dict):
        # Anthropic-style dicts may carry tool_use ``input`` (JSON) or
        # tool_result ``content``; OpenAI-style dicts carry ``text``.
        n = count_tokens(str(block.get("text", "") or block.get("content", "")))
        if "input" in block:
            n += count_tokens(str(block.get("input") or ""))
        return n
    # Anthropic SDK object — duck-type via attribute access.
    n = 0
    text = getattr(block, "text", None)
    if text:
        n += count_tokens(str(text))
    inp = getattr(block, "input", None)
    if inp is not None:
        n += count_tokens(str(inp))
    name = getattr(block, "name", None)
    if name:
        n += count_tokens(str(name))
    inner = getattr(block, "content", None)
    if inner is not None and not isinstance(inner, (str, bytes)):
        # ``content`` of a tool_result can itself be a list of blocks.
        if isinstance(inner, list):
            for sub in inner:
                n += _count_block_tokens(sub)
        else:
            n += count_tokens(str(inner))
    elif isinstance(inner, str):
        n += count_tokens(inner)
    return n


def count_message_tokens(messages: list) -> int:
    """Approximate the token cost of a chat-format message list.

    Accepts both dict-shaped messages (OpenAI/local) and objects holding
    ``role``/``content`` attributes. ``content`` may be a ``str``, a
    list of dict blocks, or a list of Anthropic SDK block objects — all
    three are walked so the budget reflects what is actually wired-on.
    """
    total = 0
    for m in messages:
        # Allow both dicts and SDK message objects (defensive).
        if isinstance(m, dict):
            content = m.get("content")
            tool_calls = m.get("tool_calls") or []
        else:
            content = getattr(m, "content", None)
            tool_calls = getattr(m, "tool_calls", None) or []

        if isinstance(content, str):
            total += count_tokens(content)
        elif isinstance(content, list):
            for block in content:
                total += _count_block_tokens(block)
        elif content is not None:
            # Single block object (Anthropic ToolUseBlock, etc.).
            total += _count_block_tokens(content)

        # OpenAI-style explicit tool_calls.
        for tc in tool_calls:
            if isinstance(tc, dict):
                fn = tc.get("function") or {}
                total += count_tokens(str(fn.get("arguments", "")))
                total += count_tokens(str(fn.get("name", "")))
            else:
                fn = getattr(tc, "function", None)
                total += count_tokens(str(getattr(fn, "arguments", "") or ""))
                total += count_tokens(str(getattr(fn, "name", "") or ""))
        total += 4  # per-message overhead (role tags, etc.)
    return total
