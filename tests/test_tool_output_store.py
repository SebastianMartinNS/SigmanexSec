"""Tests for core.tool_output_store — canonical tool output persistence."""
from __future__ import annotations

import gzip
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.time_utils import utcnow as _sap_utcnow
from core.tool_output_store import (
    ToolOutputStore,
    ToolOutputRef,
    reset_tool_output_store,
)


@pytest.fixture()
def store(tmp_paths):
    reset_tool_output_store()
    s = ToolOutputStore(
        db_path=str(tmp_paths["sessions"] / "assessments.db"),
        sessions_root=tmp_paths["sessions"],
    )
    return s


@pytest.mark.asyncio
async def test_store_small_output_uncompressed(store, tmp_paths):
    await store.init()
    payload = b"hello world\nsmall output\n"
    ref = await store.store(
        run_id="run_test1",
        tool="nmap",
        command_redacted="nmap -sV 10.0.0.1",
        stdout=payload,
        stderr=b"",
        returncode=0,
        duration_seconds=0.1,
        engagement_id="eng1",
        target="10.0.0.1",
    )
    assert isinstance(ref, ToolOutputRef)
    assert ref.stdout_compressed is False
    assert ref.stdout_bytes == len(payload)
    fp = tmp_paths["sessions"] / ref.stdout_path
    assert fp.exists()
    assert fp.read_bytes() == payload
    # URI shape
    assert ref.uri("stdout") == f"sap://run/run_test1/output/{ref.call_id}/stdout"


@pytest.mark.asyncio
async def test_store_large_output_gzipped(store, tmp_paths):
    big = (b"A" * 1024) * 1500  # ~1.5 MiB
    ref = await store.store(
        run_id="run_big",
        tool="masscan",
        command_redacted="masscan -p1-65535 10.0.0.0/24",
        stdout=big,
        stderr=b"x" * 10,
        returncode=0,
        duration_seconds=2.5,
    )
    assert ref.stdout_compressed is True
    fp = tmp_paths["sessions"] / ref.stdout_path
    assert fp.exists() and fp.suffix == ".gz"
    with gzip.open(fp, "rb") as f:
        assert f.read() == big


@pytest.mark.asyncio
async def test_read_full_head_tail_range(store):
    payload = b"".join(f"line{i:04d}\n".encode() for i in range(100))
    ref = await store.store(
        run_id="run_r",
        tool="nikto",
        command_redacted="nikto -h http://x",
        stdout=payload,
        stderr=b"",
        returncode=0,
        duration_seconds=0.0,
    )
    assert await store.read(ref.call_id) == payload
    assert await store.read(ref.call_id, head=20) == payload[:20]
    assert await store.read(ref.call_id, tail=15) == payload[-15:]
    assert await store.read(ref.call_id, offset=8, length=8) == payload[8:16]


@pytest.mark.asyncio
async def test_read_tail_on_compressed(store):
    big = (b"X" * 1024) * 1100  # > 1 MiB
    ref = await store.store(
        run_id="run_gz",
        tool="sqlmap",
        command_redacted="sqlmap --batch -u http://x",
        stdout=big,
        stderr=b"",
        returncode=0,
        duration_seconds=0.0,
    )
    assert ref.stdout_compressed
    assert await store.read(ref.call_id, tail=100) == big[-100:]
    assert await store.read(ref.call_id, head=50) == big[:50]


@pytest.mark.asyncio
async def test_list_filters_by_run_and_engagement(store):
    for i in range(3):
        await store.store(
            run_id="rA", tool="nmap",
            command_redacted=f"nmap {i}",
            stdout=b"x", stderr=b"",
            returncode=0, duration_seconds=0.0,
            engagement_id="eng1",
        )
    for i in range(2):
        await store.store(
            run_id="rB", tool="nikto",
            command_redacted=f"nikto {i}",
            stdout=b"x", stderr=b"",
            returncode=0, duration_seconds=0.0,
            engagement_id="eng2",
        )

    by_run = await store.list(run_id="rA")
    assert len(by_run) == 3 and all(r.run_id == "rA" for r in by_run)

    by_eng = await store.list(engagement_id="eng2")
    assert len(by_eng) == 2 and all(r.engagement_id == "eng2" for r in by_eng)

    by_tool = await store.list(tool="nikto")
    assert len(by_tool) == 2 and all(r.tool == "nikto" for r in by_tool)


@pytest.mark.asyncio
async def test_get_returns_ref_and_missing_returns_none(store):
    ref = await store.store(
        run_id="rg", tool="hashid", command_redacted="hashid x",
        stdout=b"y", stderr=b"", returncode=0, duration_seconds=0.0,
    )
    fetched = await store.get(ref.call_id)
    assert fetched is not None and fetched.call_id == ref.call_id
    assert (await store.get("call_does_not_exist")) is None


@pytest.mark.asyncio
async def test_artifacts_dir_created_and_listable(store, tmp_paths):
    ref = await store.store(
        run_id="ra", tool="nmap", command_redacted="nmap -oA artifacts/nmap 10.0.0.1",
        stdout=b"", stderr=b"", returncode=0, duration_seconds=0.0,
    )
    adir = tmp_paths["sessions"] / ref.artifacts_dir
    assert adir.exists() and adir.is_dir()
    (adir / "nmap.xml").write_bytes(b"<nmaprun/>")
    files = store.list_artifacts(ref)
    assert len(files) == 1 and files[0].name == "nmap.xml"


@pytest.mark.asyncio
async def test_gc_deletes_old_and_keeps_active(store, tmp_paths):
    # Create 3 outputs; we'll backdate created_at directly in the DB.
    refs = []
    for i in range(3):
        r = await store.store(
            run_id=f"r{i}", tool="nmap", command_redacted=f"nmap {i}",
            stdout=b"x", stderr=b"", returncode=0, duration_seconds=0.0,
            engagement_id=f"eng{i}",
        )
        refs.append(r)

    # Backdate the first two by 200 days.
    import aiosqlite
    old_iso = (_sap_utcnow() - timedelta(days=200)).isoformat(timespec="seconds")
    async with aiosqlite.connect(str(tmp_paths["sessions"] / "assessments.db")) as db:
        await db.execute(
            "UPDATE tool_outputs SET created_at = ? WHERE call_id IN (?, ?)",
            (old_iso, refs[0].call_id, refs[1].call_id),
        )
        await db.commit()

    # Dry run reports candidates without deleting.
    plan = await store.gc(retention_days=90, dry_run=True)
    assert plan["candidates"] == 2 and plan["deleted_rows"] == 0

    # Real GC, but keep eng0 active → only refs[1] should be deleted.
    res = await store.gc(retention_days=90, keep_engagement_ids={"eng0"})
    assert res["deleted_rows"] == 1
    assert (tmp_paths["sessions"] / refs[1].stdout_path).exists() is False
    assert (tmp_paths["sessions"] / refs[0].stdout_path).exists() is True
    assert (await store.get(refs[1].call_id)) is None
    assert (await store.get(refs[0].call_id)) is not None
