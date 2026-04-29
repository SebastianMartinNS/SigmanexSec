"""MemGPT-style long-term memory layer for the pentest agent.

Key abstractions:
  - ``MemoryManager``: facade combining core blocks, recall (FTS5),
    archival (vector store), and an LLM-driven summarizer.
  - Builtin LLM tools: ``memory_edit``, ``memory_append``,
    ``archival_insert``, ``archival_search``, ``recall_search``.

Design goals:
  - Zero hard dependencies beyond aiosqlite (sentence-transformers,
    sqlite-vec and tiktoken are optional with graceful fallbacks).
  - Per-engagement isolation by default; cross-engagement archival
    search is opt-in.
  - Drop-in replacement for the orchestrator's in-memory ``messages``
    list via ``MemoryManager.build_context()``.
"""
from __future__ import annotations

from core.memory.manager import MemoryManager
from core.memory.tools import BUILTIN_TOOL_NAMES, builtin_tool_specs

__all__ = ["MemoryManager", "BUILTIN_TOOL_NAMES", "builtin_tool_specs"]
