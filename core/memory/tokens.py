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


def count_message_tokens(messages: list[dict]) -> int:
    """Approximate the token cost of a chat-format message list."""
    total = 0
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            total += count_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total += count_tokens(str(block.get("content", "") or block.get("text", "")))
        # Tool-call argument JSON
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") or {}
            total += count_tokens(str(fn.get("arguments", "")))
            total += count_tokens(str(fn.get("name", "")))
        total += 4  # per-message overhead (role tags, etc.)
    return total
