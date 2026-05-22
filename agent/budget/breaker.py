"""
agent/budget/breaker.py — Fuzzy circuit-breaker for tool repetition.

Extracted from ``agent/orchestrator.py`` (formerly the
``_tool_call_signature`` / ``_canonicalise_url`` / ``_tool_call_token_set``
helpers and the ``_fuzzy_signature`` index). Behaviour is preserved
bit-for-bit: a thin delegate in :class:`Orchestrator` forwards each
call to this module, so the breaker's Jaccard ≥ 0.85 contract still
holds for every legacy test.

Two normalisations make the breaker robust to LLM permutation tactics:

* URL-aware: ``http://x``, ``https://x``, ``https://www.x/`` all collapse
  to the bare host.
* CSV-aware: known list-valued args (``severity`` etc.) split on ``,``
  so adding/removing a level bumps Jaccard, not the signature.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

# Keys whose CSV values should be tokenised individually so that
# ``severity="critical,high"`` and ``severity="critical,high,medium"``
# share most tokens (closes the Phase 3 loophole where the LLM appended
# one more level to bypass the breaker).
CSV_TOKENISE_KEYS: frozenset[str] = frozenset({
    "severity", "tags", "templates", "ports", "levels", "extensions",
    "wordlists", "modules",
})


def tool_call_signature(name: str, args: dict) -> str:
    """SHA1 signature for an exact ``(name, args)`` invocation.

    sha1 is used as a non-cryptographic content hash — collision attacks
    are not in this code path's threat model. ``usedforsecurity=False``
    documents the intent and silences both ruff (S324) and bandit (B324).
    """
    try:
        payload = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        payload = repr(args)
    return hashlib.sha1(  # noqa: S324
        f"{name}|{payload}".encode(),
        usedforsecurity=False,
    ).hexdigest()


def canonicalise_url(value: str) -> str:
    """Reduce a URL to its host part (lowercase, no ``www.``).

    Returns the original string when it does not look like an HTTP URL
    or parsing fails. Best-effort; never raises.
    """
    if not isinstance(value, str):
        return value
    if not value[:8].lower().startswith(("http://", "https://")):
        return value
    try:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host or value
    except Exception:
        return value


def tool_call_token_set(name: str, args: dict) -> frozenset[str]:
    """Bag-of-tokens used by :class:`FuzzyBreaker` to compute Jaccard."""
    out: set[str] = {f"@{name}"}
    canon_args: dict = {}
    try:
        for key, val in (args or {}).items():
            if isinstance(val, str):
                canon = canonicalise_url(val)
                canon_args[key] = canon
                if key in CSV_TOKENISE_KEYS and "," in canon:
                    for piece in canon.split(","):
                        piece = piece.strip()
                        if piece:
                            out.add(piece.lower())
                else:
                    out.add(canon.lower()[:64])
            elif isinstance(val, (list, tuple)):
                canon_args[key] = list(val)
                for item in val:
                    if isinstance(item, str) and item:
                        out.add(item.lower()[:64])
            else:
                canon_args[key] = val
    except Exception:
        canon_args = args if isinstance(args, dict) else {}

    try:
        payload = json.dumps(canon_args, sort_keys=True, default=str)
    except Exception:
        payload = repr(canon_args)
    for tok in re.findall(r"[A-Za-z0-9_.:/\\-]+", payload):
        if tok and len(tok) <= 64:
            out.add(tok.lower())
    return frozenset(out)


class FuzzyBreaker:
    """Sliding-window Jaccard fuzzy matcher.

    The breaker keeps the last 256 ``(token_set, signature)`` pairs and
    collapses near-duplicate invocations onto the *earlier* signature so
    the upstream counter increments the same bucket. This is what stops
    the LLM from bypassing the limit by appending a no-op flag.
    """

    __slots__ = ("_threshold", "_index", "_cap")

    def __init__(self, *, threshold: float = 0.85, cap: int = 512) -> None:
        if not (0.0 < threshold <= 1.0):
            raise ValueError(f"threshold must be in (0, 1], got {threshold}")
        self._threshold = threshold
        self._cap = max(64, cap)
        self._index: list[tuple[frozenset[str], str]] = []

    def signature(self, name: str, args: dict) -> str:
        """Return the signature for a new call, fuzzy-matching against the
        recent history when possible.

        Same semantics as the legacy ``Orchestrator._fuzzy_signature``
        (Jaccard ≥ threshold collapses onto the prior signature).
        """
        new_tokens = tool_call_token_set(name, args)
        exact_sig = tool_call_signature(name, args)
        best: tuple[float, str] | None = None
        for tokens, prior_sig in self._index[-256:]:
            if not tokens or not new_tokens:
                continue
            inter = len(tokens & new_tokens)
            if not inter:
                continue
            union = len(tokens | new_tokens)
            jaccard = inter / union if union else 0.0
            if jaccard >= self._threshold and (best is None or jaccard > best[0]):
                best = (jaccard, prior_sig)
        chosen = best[1] if best is not None else exact_sig
        self._index.append((new_tokens, chosen))
        if len(self._index) > self._cap:
            self._index = self._index[-(self._cap // 2):]
        return chosen

    def reset(self) -> None:
        self._index.clear()

    @property
    def size(self) -> int:
        return len(self._index)
