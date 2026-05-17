"""MemoryManager — facade used by the orchestrator.

Responsibilities:
  - Persist every message to the recall store (FTS5 search by the agent).
  - Keep a small, always-visible set of core memory blocks rendered into
    the system prompt.
  - Maintain a sliding window of "active" recent messages, summarizing
    older ones into a single system block when the projected token cost
    exceeds the configured budget.
  - Provide an archival vector store for cross-turn / cross-run recall.
  - Expose a uniform ``handle_builtin_tool()`` entry point so the
    orchestrator can route memory-related tool calls without special
    casing.
"""
from __future__ import annotations

import asyncio
import json
import os

from core.memory.blocks import DEFAULT_BLOCKS, MemoryBlock, render_blocks
from core.memory.embeddings import EmbeddingProvider, cosine
from core.memory.store import MemoryStore
from core.memory.summarizer import SummaryFn, summarize
from core.memory.tokens import count_message_tokens

# Defaults; the orchestrator overrides them from config.yaml.
DEFAULT_CTX_TOKENS = int(os.environ.get("SAP_CTX_BUDGET_TOKENS", "32000"))
DEFAULT_TRIGGER_TOKENS = int(os.environ.get("SAP_SUMMARY_TRIGGER_TOKENS", "24000"))
DEFAULT_KEEP_RECENT = int(os.environ.get("SAP_KEEP_RECENT_MESSAGES", "12"))


class MemoryManager:
    """Per-engagement, per-run memory facade.

    Use one instance per ``run_agent()`` invocation. Multiple managers
    can share the same underlying ``MemoryStore``.
    """

    def __init__(
        self,
        engagement_id: str,
        run_id: str,
        *,
        store: MemoryStore | None = None,
        embedder: EmbeddingProvider | None = None,
        summary_fn: SummaryFn | None = None,
        ctx_budget_tokens: int = DEFAULT_CTX_TOKENS,
        summary_trigger_tokens: int = DEFAULT_TRIGGER_TOKENS,
        keep_recent: int = DEFAULT_KEEP_RECENT,
        archival_global: bool = False,
    ):
        self.engagement_id = engagement_id
        self.run_id = run_id
        self._store = store or MemoryStore()
        self._embedder = embedder or EmbeddingProvider()
        self._summary_fn = summary_fn
        self._ctx_budget = ctx_budget_tokens
        self._trigger = summary_trigger_tokens
        self._keep_recent = keep_recent
        self._archival_global = archival_global
        # Cursor: messages with seq < self._summary_cursor are considered
        # already collapsed into self._summary_text.
        self._summary_cursor: int = 0
        self._summary_text: str = ""
        self._init_lock = asyncio.Lock()
        self._initialized = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self, engagement_record: dict | None = None) -> None:
        async with self._init_lock:
            if self._initialized:
                return
            await self._store.init()
            # Seed default blocks lazily (only those missing).
            existing = {label for label, _, _ in await self._store.list_blocks(self.engagement_id)}
            for label, (initial, cap) in DEFAULT_BLOCKS.items():
                if label in existing:
                    continue
                value = initial
                if label == "engagement" and engagement_record:
                    value = _format_engagement_block(engagement_record)
                await self._store.upsert_block(self.engagement_id, label, value, cap)
            self._initialized = True

    def set_summary_fn(self, fn: SummaryFn) -> None:
        self._summary_fn = fn

    # ------------------------------------------------------------------
    # Core blocks
    # ------------------------------------------------------------------

    async def get_blocks(self) -> list[MemoryBlock]:
        rows = await self._store.list_blocks(self.engagement_id)
        return [MemoryBlock(label=label, value=value, max_chars=cap) for label, value, cap in rows]

    async def edit_block(self, label: str, value: str) -> str:
        existing = await self._store.get_block(self.engagement_id, label)
        cap = existing[1] if existing else DEFAULT_BLOCKS.get(label, ("", 2000))[1]
        await self._store.upsert_block(self.engagement_id, label, value, cap)
        return f"block '{label}' updated ({len(value)}/{cap} chars)"

    async def append_block(self, label: str, text: str, sep: str = "\n") -> str:
        existing = await self._store.get_block(self.engagement_id, label)
        if existing is None:
            cap = DEFAULT_BLOCKS.get(label, ("", 2000))[1]
            new_value = text
        else:
            old, cap = existing
            new_value = (old + sep + text) if old else text
        if len(new_value) > cap:
            new_value = new_value[-cap:]
        await self._store.upsert_block(self.engagement_id, label, new_value, cap)
        return f"block '{label}' appended ({len(new_value)}/{cap} chars)"

    # ------------------------------------------------------------------
    # Recall (FTS over messages)
    # ------------------------------------------------------------------

    async def recall_search(
        self, query: str, *, k: int = 10, role: str | None = None
    ) -> list[dict]:
        return await self._store.fts_search(
            self.engagement_id, query, k=k, role=role
        )

    # ------------------------------------------------------------------
    # Archival (vector store)
    # ------------------------------------------------------------------

    async def archival_insert(
        self, text: str, *, source: str | None = None, metadata: dict | None = None
    ) -> int:
        vec = self._embedder.embed(text)
        meta = json.dumps(metadata) if metadata else None
        return await self._store.insert_archival(
            self.engagement_id, text, vec, source=source, metadata=meta
        )

    async def archival_search(
        self, query: str, *, k: int = 5, scope_global: bool = False
    ) -> list[dict]:
        qvec = self._embedder.embed(query)
        eng = None if (scope_global and self._archival_global) else self.engagement_id
        candidates = await self._store.list_archival(eng)
        scored = [
            (cosine(qvec, c["embedding"]) if c["embedding"] else 0.0, c)
            for c in candidates
        ]
        scored.sort(key=lambda x: x[0], reverse=True)
        out = []
        for score, c in scored[:k]:
            out.append({
                "id": c["id"],
                "score": round(float(score), 4),
                "source": c["source"],
                "ts": c["ts"],
                "text": c["text"],
            })
        return out

    # ------------------------------------------------------------------
    # Message recording + context construction
    # ------------------------------------------------------------------

    async def record(
        self,
        role: str,
        content: str,
        *,
        tool_call_id: str | None = None,
        tool_name: str | None = None,
    ) -> int:
        return await self._store.append_message(
            self.engagement_id,
            self.run_id,
            role,
            content,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
        )

    async def build_context(
        self,
        *,
        system_prompt: str,
        user_input: str | None = None,
        _compacted: bool = False,
    ) -> list[dict]:
        """Assemble the message list to send to the LLM this turn.

        Layout:
          [0] system: SYSTEM_PROMPT + rendered core blocks (+ summary, if any)
          [1..]      replayed recent messages (post summary cursor)
          [last]     optional fresh user_input (only if not already recorded)
        """
        await self.initialize()
        blocks = await self.get_blocks()
        block_text = render_blocks(blocks)

        sys_parts = [system_prompt, block_text]
        if self._summary_text:
            sys_parts.append(
                "<recap_of_earlier_conversation>\n"
                + self._summary_text
                + "\n</recap_of_earlier_conversation>"
            )
        merged_system = "\n\n".join(p for p in sys_parts if p).strip()

        recent_rows = await self._store.get_messages_since(
            self.engagement_id, self._summary_cursor
        )
        replay = [_row_to_chat_msg(r) for r in recent_rows]

        messages: list[dict] = [{"role": "system", "content": merged_system}]
        messages.extend(replay)

        if user_input:
            if not replay or not (
                replay[-1].get("role") == "user"
                and replay[-1].get("content") == user_input
            ):
                messages.append({"role": "user", "content": user_input})

        # Token budget enforcement: at most one compaction per build to avoid
        # unbounded recursion when even the compacted form is over budget.
        if not _compacted and count_message_tokens(messages) >= self._trigger:
            previous_cursor = self._summary_cursor
            await self._compact(merged_system, replay)
            if self._summary_cursor > previous_cursor:
                return await self.build_context(
                    system_prompt=system_prompt,
                    user_input=user_input,
                    _compacted=True,
                )
        return messages

    async def _compact(self, current_system: str, replay: list[dict]) -> None:
        """Move the oldest half of the replayable messages into the summary."""
        if not replay:
            return
        keep = self._keep_recent
        if len(replay) <= keep:
            # Even with everything kept we're over budget — compact aggressively.
            keep = max(2, len(replay) // 4)
        to_summarize_count = len(replay) - keep
        rows = await self._store.get_messages_since(
            self.engagement_id, self._summary_cursor
        )
        old_rows = rows[:to_summarize_count]
        if not old_rows:
            return
        text_summary = await summarize(
            [{"role": r["role"], "content": r["content"], "tool_name": r["tool_name"]} for r in old_rows],
            self._summary_fn,
        )
        prev = self._summary_text
        self._summary_text = (
            (prev + "\n\n" + text_summary).strip() if prev else text_summary
        )
        # Trim summary itself if it grows too large. Phase 5: preserve
        # both the HEAD (earliest tactical decisions — they explain *why*
        # the run is shaped this way) and the TAIL (most recent state),
        # bridged with an explicit marker so the LLM never silently
        # forgets the original mission.
        max_summary_chars = 6000
        if len(self._summary_text) > max_summary_chars:
            head = max_summary_chars // 3
            tail = max_summary_chars - head - 32  # leave room for marker
            marker = "\n\n[...summary middle elided...]\n\n"
            self._summary_text = (
                self._summary_text[:head] + marker + self._summary_text[-tail:]
            )
        new_cursor = old_rows[-1]["seq"] + 1
        self._summary_cursor = new_cursor
        await self._store.mark_summarized([r["id"] for r in old_rows])

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def stats(self) -> dict:
        rows = await self._store.get_messages_since(self.engagement_id, 0)
        return {
            "engagement_id": self.engagement_id,
            "run_id": self.run_id,
            "total_messages": len(rows),
            "summary_cursor": self._summary_cursor,
            "summary_chars": len(self._summary_text),
            "embedding_backend": self._embedder.backend,
        }


# ---------- helpers ----------

def _row_to_chat_msg(row: dict) -> dict:
    msg: dict = {"role": row["role"], "content": row["content"] or ""}
    if row.get("tool_call_id"):
        msg["tool_call_id"] = row["tool_call_id"]
    return msg


def _format_engagement_block(eng: dict) -> str:
    parts = [
        f"id: {eng.get('id', '?')}",
        f"name: {eng.get('name', '?')}",
        f"client: {eng.get('client', '?')}",
        f"phase: {eng.get('current_phase') or eng.get('phase', '?')}",
    ]
    for label, key in (("scope_cidrs", "scope_cidrs"), ("scope_domains", "scope_domains"), ("scope_urls", "scope_urls")):
        v = eng.get(key)
        if v:
            parts.append(f"{label}: {', '.join(v) if isinstance(v, (list, tuple)) else v}")
    return "\n".join(parts)
