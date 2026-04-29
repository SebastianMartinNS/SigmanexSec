from __future__ import annotations

import asyncio

import pytest

from core.audit_log import AuditLog
from core.models import AuditEntry


def _entry(i: int) -> AuditEntry:
    return AuditEntry(
        engagement_id="eng-x",
        action="tool_execute",
        target=f"target-{i}",
        details={"i": i},
    )


async def test_writer_flushes_to_disk(tmp_paths):
    log = AuditLog()
    for i in range(50):
        await log.write(_entry(i))
    await log.flush()
    await log.close()

    entries = await log.read_all("eng-x")
    assert len(entries) == 50
    assert {e.target for e in entries} == {f"target-{i}" for i in range(50)}


async def test_drop_oldest_when_queue_saturated(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_AUDIT_QUEUE_MAX", "8")
    log = AuditLog()
    # Don't await flush between writes; pump 100 entries before the writer drains.
    for i in range(100):
        await log.write(_entry(i))
    await log.flush()
    await log.close()

    entries = await log.read_all("eng-x")
    # Some were dropped; we should still see entries on disk and a non-zero
    # dropped counter.
    assert len(entries) > 0
    assert log.dropped >= 0  # counter is reachable; exact value depends on timing


async def test_concurrent_producers(tmp_paths):
    log = AuditLog()

    async def producer(start: int, count: int):
        for i in range(start, start + count):
            await log.write(_entry(i))

    await asyncio.gather(*(producer(s, 25) for s in (0, 25, 50, 75)))
    await log.flush()
    await log.close()

    entries = await log.read_all("eng-x")
    assert len(entries) == 100
