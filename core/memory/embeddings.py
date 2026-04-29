"""Embedding provider with optional sentence-transformers backend.

If ``sentence-transformers`` is installed (and the configured model can
be loaded), we use it. Otherwise we fall back to a deterministic
hash-based projection that yields stable, comparable vectors — enough
for unit tests and for archival search to *function* (semantic quality
will be poor, but no crashes).

Models are loaded lazily on first ``embed()`` call to keep cold start fast.
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
from typing import Optional

_DEFAULT_MODEL = os.environ.get(
    "SAP_EMBEDDING_MODEL", "intfloat/multilingual-e5-small"
)
_DEFAULT_DIM = int(os.environ.get("SAP_EMBEDDING_DIM", "384"))


class EmbeddingProvider:
    def __init__(self, model_name: Optional[str] = None, dim: int = _DEFAULT_DIM):
        self._model_name = model_name or _DEFAULT_MODEL
        self._dim = dim
        self._model = None
        self._tried = False

    @property
    def dim(self) -> int:
        return self._dim

    @property
    def backend(self) -> str:
        if self._model is not None:
            return f"sentence-transformers:{self._model_name}"
        return "fallback-hash"

    def _try_load(self) -> None:
        if self._tried:
            return
        self._tried = True
        if os.environ.get("SAP_DISABLE_ST", "").lower() in ("1", "true", "yes"):
            return
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            self._model = SentenceTransformer(self._model_name)
            try:
                self._dim = int(self._model.get_sentence_embedding_dimension())
            except Exception:  # pragma: no cover
                pass
        except Exception:
            self._model = None  # fallback path remains active

    def embed(self, text: str) -> list[float]:
        if not text:
            return [0.0] * self._dim
        self._try_load()
        if self._model is not None:
            vec = self._model.encode(
                # e5-family expects "query: ..." / "passage: ..." prefixes,
                # but using the plain text degrades to a still-useful score.
                text,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            return [float(x) for x in vec]
        return _hash_embed(text, self._dim)


def _hash_embed(text: str, dim: int) -> list[float]:
    """Deterministic hash-based projection (BoW over SHA-256 chunks)."""
    vec = [0.0] * dim
    for token in text.lower().split():
        h = hashlib.sha256(token.encode()).digest()
        # 8 floats per hash (32 bytes / 4)
        for i in range(8):
            offset = i * 4
            (val,) = struct.unpack(">i", h[offset : offset + 4])
            vec[(int.from_bytes(h[offset : offset + 4], "big") + i) % dim] += (
                val / 2_147_483_647.0
            )
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / norm for x in vec]


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))  # both are L2-normalized
