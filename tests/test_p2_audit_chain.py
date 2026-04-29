"""
P2.1 — Audit log BLAKE2b hash chain.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from core.audit_log import AuditLog, verify_audit_chain
from core.models import AuditEntry


@pytest.mark.asyncio
async def test_chain_links_each_entry(tmp_path):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(5):
        await log.write(AuditEntry(engagement_id="e", actor="t", action=f"a{i}"))
    await log.flush()
    await log.close()

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 5
    prev = ""
    for raw in lines:
        obj = json.loads(raw)
        assert obj["_prev"] == prev
        assert isinstance(obj["_hash"], str) and len(obj["_hash"]) == 64
        prev = obj["_hash"]


@pytest.mark.asyncio
async def test_verify_audit_chain_accepts_clean_log(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    for i in range(8):
        await log.write(AuditEntry(engagement_id="e", actor="t", action=f"a{i}"))
    await log.flush()
    await log.close()

    ok, n, msg = verify_audit_chain(p)
    assert ok and n == 8, msg


@pytest.mark.asyncio
async def test_verify_audit_chain_detects_field_tamper(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    for i in range(4):
        await log.write(AuditEntry(engagement_id="e", actor="t", action=f"a{i}"))
    await log.flush()
    await log.close()

    # Tamper with line 3: change `action` but keep `_hash` → mismatch.
    lines = p.read_text().splitlines()
    obj = json.loads(lines[2])
    obj["action"] = "tampered"
    lines[2] = json.dumps(obj, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")

    ok, n, msg = verify_audit_chain(p)
    assert not ok and n == 3
    assert "hash" in msg


@pytest.mark.asyncio
async def test_verify_audit_chain_detects_deleted_entry(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    for i in range(4):
        await log.write(AuditEntry(engagement_id="e", actor="t", action=f"a{i}"))
    await log.flush()
    await log.close()

    # Drop the second entry; the third should now have a `_prev` that
    # no longer matches the recomputed previous hash.
    lines = p.read_text().splitlines()
    p.write_text(lines[0] + "\n" + lines[2] + "\n" + lines[3] + "\n")

    ok, n, msg = verify_audit_chain(p)
    assert not ok
    assert "chain" in msg or "hash" in msg


@pytest.mark.asyncio
async def test_chain_resumes_across_restarts(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    await log.write(AuditEntry(engagement_id="e", actor="t", action="first"))
    await log.flush()
    await log.close()

    # Re-instantiate (simulates process restart) and append more entries.
    log2 = AuditLog(str(p))
    await log2.write(AuditEntry(engagement_id="e", actor="t", action="second"))
    await log2.write(AuditEntry(engagement_id="e", actor="t", action="third"))
    await log2.flush()
    await log2.close()

    ok, n, msg = verify_audit_chain(p)
    assert ok and n == 3, msg


@pytest.mark.asyncio
async def test_read_all_strips_chain_metadata(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = AuditLog(str(p))
    await log.write(AuditEntry(engagement_id="x", actor="t", action="hi"))
    await log.flush()
    entries = await log.read_all()
    await log.close()
    assert len(entries) == 1
    # Public model has no _prev / _hash and validates cleanly.
    assert entries[0].action == "hi"
