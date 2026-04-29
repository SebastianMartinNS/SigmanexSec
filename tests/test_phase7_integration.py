"""Phase 7: end-to-end integration of the ToolOutputStore + executor."""
from __future__ import annotations

import asyncio
import gzip
import os
from datetime import datetime, timedelta
from pathlib import Path

import aiosqlite
import pytest

from core.executor import ToolExecutor
from core.models import Phase
from core.time_utils import utcnow as _sap_utcnow
from core.tool_output_store import (
    get_tool_output_store, reset_tool_output_store,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _allow(monkeypatch, *binaries: str) -> None:
    monkeypatch.setattr(
        "core.executor._allowed_tools", lambda: set(binaries)
    )


@pytest.fixture(autouse=True)
def _isolate_store(tmp_paths):
    reset_tool_output_store()
    yield
    reset_tool_output_store()


# ── Byte-equivalence integration ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_persisted_stdout_matches_subprocess_byte_for_byte(monkeypatch, tmp_paths):
    """Capture a known printf payload through executor and verify on-disk bytes match exactly."""
    _allow(monkeypatch, "printf")
    expected = "BEGIN\n" + ("LINE_%05d\n" % 0) + ("X" * 4096) + "\nEND\n"
    payload = expected.replace("\\", "\\\\").replace("%", "%%")  # printf-safe

    exe = ToolExecutor(run_id="run_e2e_1")
    result = await exe.run(
        tool="printf",
        args=[payload],
        engagement_id="eng_e2e",
        phase=Phase.RECON,
        timeout=10,
    )
    assert result.returncode == 0
    assert result.output_ref is not None
    assert result.output_ref.run_id == "run_e2e_1"

    store = get_tool_output_store()
    on_disk = await store.read(result.call_id, "stdout")
    # Subprocess stdout must equal expected (printf does no trailing newline of its own)
    assert on_disk == expected.encode("utf-8")
    assert result.stdout_bytes_full == len(expected.encode("utf-8"))


# ── Massive output: gzip + no truncation on disk ────────────────────────────

@pytest.mark.asyncio
async def test_large_output_persisted_uncapped_with_gzip(monkeypatch, tmp_paths):
    """Generate a 2 MiB stdout via /bin/dd, verify gzip + full disk persistence."""
    if not Path("/bin/dd").exists() and not Path("/usr/bin/dd").exists():
        pytest.skip("dd not available")
    _allow(monkeypatch, "dd")
    # Force in-memory cap small to verify the truncation flag while disk stays full.
    monkeypatch.setattr("core.executor._max_output", lambda: 65536)

    exe = ToolExecutor(run_id="run_e2e_big")
    result = await exe.run(
        tool="dd",
        args=["if=/dev/zero", "bs=1M", "count=2", "status=none"],
        engagement_id="eng_big", phase=Phase.RECON, timeout=30,
    )
    assert result.returncode == 0
    assert len(result.stdout) == 65536
    assert result.truncated is True
    assert result.output_ref is not None
    assert result.output_ref.stdout_compressed is True
    on_disk = await get_tool_output_store().read(result.call_id, "stdout")
    assert len(on_disk) == 2 * 1024 * 1024
    assert on_disk == b"\x00" * (2 * 1024 * 1024)


# ── Concurrency: 30 parallel calls, zero losses ─────────────────────────────

@pytest.mark.asyncio
async def test_concurrent_calls_no_losses(monkeypatch, tmp_paths):
    _allow(monkeypatch, "printf")
    N = 30
    exe = ToolExecutor(run_id="run_concurrency")

    async def _one(i: int):
        return await exe.run(
            tool="printf", args=[f"call-{i:03d}\n"],
            engagement_id="eng_c", phase=Phase.RECON, timeout=10,
        )

    results = await asyncio.gather(*[_one(i) for i in range(N)])
    assert all(r.returncode == 0 for r in results)
    call_ids = {r.call_id for r in results}
    assert len(call_ids) == N  # all unique

    # Every call must be retrievable from the SQLite index
    refs = await get_tool_output_store().list(run_id="run_concurrency", limit=N + 5)
    assert len(refs) == N

    # And every persisted stdout must match its expected payload
    for r in results:
        on_disk = await get_tool_output_store().read(r.call_id, "stdout")
        expected = f"call-{int(r.command.split('-')[1].split(chr(10))[0]):03d}\n"
        assert on_disk == expected.encode("utf-8")


# ── GC retention boundary ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_gc_retention_boundary(tmp_paths):
    store = get_tool_output_store()

    async def _make(call_id: str, eng: str, days_old: int):
        ref = await store.store(
            run_id="run_gc", tool="t", command_redacted="t",
            stdout=b"x", stderr=b"", returncode=0, duration_seconds=0.0,
            engagement_id=eng, call_id=call_id,
        )
        # Backdate created_at
        old = (_sap_utcnow() - timedelta(days=days_old)).isoformat(timespec="seconds")
        async with aiosqlite.connect(store._db_path) as db:
            await db.execute(
                "UPDATE tool_outputs SET created_at = ? WHERE call_id = ?",
                (old, call_id),
            )
            await db.commit()
        return ref

    fresh = await _make("call_fresh", "eng_a", 5)
    stale = await _make("call_stale", "eng_a", 100)
    keep_eng = await _make("call_keep_eng", "eng_keep", 100)

    stats = await store.gc(retention_days=30, keep_engagement_ids={"eng_keep"})
    # Only stale (90+ days, not in keep set) should be deleted
    assert stats["deleted_rows"] == 1
    assert await store.get(fresh.call_id) is not None
    assert await store.get(stale.call_id) is None
    assert await store.get(keep_eng.call_id) is not None


# ── Audit log records call_id + output_ref_uri ──────────────────────────────

@pytest.mark.asyncio
async def test_audit_log_carries_call_id_and_uri(monkeypatch, tmp_paths):
    _allow(monkeypatch, "printf")
    from core.audit_log import AuditLog
    audit_path = Path(os.environ["AUDIT_LOG_PATH"])
    audit = AuditLog(str(audit_path))
    exe = ToolExecutor(audit_log=audit, run_id="run_audit")
    result = await exe.run(
        tool="printf", args=["hi"], engagement_id="eng_audit",
        phase=Phase.RECON, timeout=10,
    )
    # Flush async writer
    await asyncio.sleep(0.1)
    await audit.aclose() if hasattr(audit, "aclose") else None

    text = audit_path.read_text()
    assert result.call_id in text
    assert "tool_complete" in text
    assert "sap://run/run_audit/output/" in text
