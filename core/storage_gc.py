"""
core/storage_gc.py — Background garbage collector for the ToolOutputStore.

Runs periodically as an asyncio task (started by the dashboard's lifespan
event) and deletes tool outputs older than the configured retention window.
Engagements explicitly marked as "keep forever" can be excluded via config.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional

from core.tool_output_store import ToolOutputStore, get_tool_output_store

_log = logging.getLogger(__name__)


async def _gc_loop(
    store: ToolOutputStore,
    retention_days: int,
    interval_seconds: int,
    keep_engagement_ids: Optional[Iterable[str]],
) -> None:
    while True:
        try:
            stats = await store.gc(
                retention_days=retention_days,
                keep_engagement_ids=set(keep_engagement_ids or []) or None,
                dry_run=False,
            )
            _log.info(
                "tool_output_store gc: candidates=%s deleted_rows=%s deleted_dirs=%s",
                stats.get("candidates", 0),
                stats.get("deleted_rows", 0),
                stats.get("deleted_dirs", 0),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover — defensive
            _log.error("tool_output_store gc failed: %s", exc)
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            raise


def start_gc_scheduler(
    *,
    retention_days: int = 90,
    interval_seconds: int = 24 * 3600,
    keep_engagement_ids: Optional[Iterable[str]] = None,
    store: Optional[ToolOutputStore] = None,
) -> asyncio.Task:
    """Start the GC loop and return its asyncio.Task. Caller owns the task."""
    store = store or get_tool_output_store()
    return asyncio.create_task(
        _gc_loop(store, retention_days, interval_seconds, keep_engagement_ids),
        name="tool_output_store_gc",
    )
