"""
core/storage_gc.py — Background garbage collector for SAP-Pentest.

Two responsibilities, both driven by the same asyncio task started by the
dashboard's lifespan event:

1. **ToolOutputStore GC** — delete persisted stdout/stderr for
   engagements older than the configured retention window. Engagements
   explicitly marked as "keep forever" can be excluded via config.

2. **Log rotation** — size- and age-based rotation of operational log
   files under ``./logs/`` (or ``SAP_LOG_ROTATE_DIR``). Rotated files
   are gzipped in place and capped to ``SAP_LOG_ROTATE_KEEP`` copies.
   The audit log (``audit.jsonl`` + its head mirror) is **excluded** —
   it has its own dedicated rotation in ``core/audit_log.py`` that
   maintains the BLAKE2b hash chain across file boundaries.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
import os
import shutil
import time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from core.tool_output_store import ToolOutputStore, get_tool_output_store

_log = logging.getLogger(__name__)


# ── Log rotation ──────────────────────────────────────────────────────────

# Files we never rotate from this routine. ``audit.jsonl`` and its head
# mirror are owned by core/audit_log.py which preserves the BLAKE2b chain
# across rotations. Anything matching one of these basenames is skipped.
_AUDIT_EXCLUDES: frozenset[str] = frozenset({"audit.jsonl", "audit.jsonl.head"})


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _rotate_one(path: Path, keep: int) -> bool:
    """Gzip a single log file in place to ``<path>.<UTC ISO>.gz`` and trim
    the rotated history to ``keep`` entries (oldest first). Returns True
    if a rotation happened, False otherwise (e.g. file already empty).
    """
    if not path.is_file():
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size == 0:
        return False

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    archive = path.with_name(f"{path.name}.{stamp}.gz")

    with path.open("rb") as src, gzip.open(archive, "wb") as dst:
        shutil.copyfileobj(src, dst)

    # Truncate the live file rather than recreate it — applications holding
    # an open file descriptor (typical for long-running daemons) keep
    # writing to the same inode without dropping records.
    try:
        with path.open("r+b") as live:
            live.truncate(0)
    except OSError:  # pragma: no cover — defensive, race with writer
        pass

    # Trim history to the configured number of archives.
    history = sorted(
        path.parent.glob(f"{path.name}.*.gz"),
        key=lambda p: p.stat().st_mtime,
    )
    for stale in history[:-keep] if keep > 0 else history:
        try:
            stale.unlink()
        except OSError:
            pass
    return True


def _rotate_logs(
    *,
    log_dir: Path | None = None,
    size_threshold_bytes: int | None = None,
    max_age: timedelta | None = None,
    keep: int | None = None,
    extra_excludes: Iterable[str] | None = None,
) -> dict[str, int]:
    """Rotate every log file in *log_dir* whose size or age exceeds the
    configured thresholds. Returns a small stats dict.

    Defaults (overridable via env or argument):

    * ``SAP_LOG_ROTATE_DIR``      (default ``./logs``)
    * ``SAP_LOG_ROTATE_SIZE_MB``  (default 100)
    * ``SAP_LOG_ROTATE_AGE_DAYS`` (default 14)
    * ``SAP_LOG_ROTATE_KEEP``     (default 14)
    """
    if log_dir is None:
        log_dir = Path(os.environ.get("SAP_LOG_ROTATE_DIR", "./logs"))
    if size_threshold_bytes is None:
        size_threshold_bytes = _env_int("SAP_LOG_ROTATE_SIZE_MB", 100) * 1024 * 1024
    if max_age is None:
        max_age = timedelta(days=_env_int("SAP_LOG_ROTATE_AGE_DAYS", 14))
    if keep is None:
        keep = _env_int("SAP_LOG_ROTATE_KEEP", 14)

    extra = frozenset(extra_excludes or ())
    skipped = _AUDIT_EXCLUDES | extra

    stats = {"considered": 0, "rotated": 0, "skipped": 0}

    if not log_dir.exists() or not log_dir.is_dir():
        return stats

    now = time.time()
    age_cutoff = now - max_age.total_seconds()

    candidates: list[Path] = []
    for pattern in ("*.log", "*.jsonl", "*.out", "*.err"):
        candidates.extend(log_dir.glob(pattern))

    for path in candidates:
        if not path.is_file():
            continue
        if path.name in skipped:
            stats["skipped"] += 1
            continue
        stats["considered"] += 1

        try:
            st = path.stat()
        except OSError:
            continue

        too_big = st.st_size >= size_threshold_bytes
        too_old = st.st_mtime <= age_cutoff
        if too_big or too_old:
            if _rotate_one(path, keep=keep):
                stats["rotated"] += 1

    return stats


# ── ToolOutputStore GC + log rotation loop ────────────────────────────────


async def _gc_loop(
    store: ToolOutputStore,
    retention_days: int,
    interval_seconds: int,
    keep_engagement_ids: Iterable[str] | None,
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

        # Log rotation runs on the same cadence; it is cheap (one stat()
        # per file, gzip only when thresholds trip) so we do not need a
        # separate timer for it.
        try:
            rotated = _rotate_logs()
            if rotated["rotated"]:
                _log.info(
                    "log rotation: considered=%s rotated=%s skipped=%s",
                    rotated["considered"],
                    rotated["rotated"],
                    rotated["skipped"],
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover — defensive
            _log.error("log rotation failed: %s", exc)

        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            raise


def start_gc_scheduler(
    *,
    retention_days: int = 90,
    interval_seconds: int = 24 * 3600,
    keep_engagement_ids: Iterable[str] | None = None,
    store: ToolOutputStore | None = None,
) -> asyncio.Task:
    """Start the GC loop and return its asyncio.Task. Caller owns the task."""
    store = store or get_tool_output_store()
    return asyncio.create_task(
        _gc_loop(store, retention_days, interval_seconds, keep_engagement_ids),
        name="tool_output_store_gc",
    )
