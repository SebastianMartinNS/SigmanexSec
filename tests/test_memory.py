from __future__ import annotations

import json

from core.memory.manager import MemoryManager
from core.memory.tools import BUILTIN_TOOL_NAMES, dispatch_builtin_tool


async def test_initialize_seeds_default_blocks(tmp_paths, engagement_id):
    mgr = MemoryManager(engagement_id, run_id="run-1")
    await mgr.initialize()
    blocks = {b.label for b in await mgr.get_blocks()}
    assert {"persona", "engagement", "targets", "findings_summary", "scratchpad"}.issubset(blocks)


async def test_edit_and_append_block(tmp_paths, engagement_id):
    mgr = MemoryManager(engagement_id, run_id="r")
    await mgr.initialize()
    await mgr.edit_block("scratchpad", "host 10.0.0.1 has ssh open")
    blocks = {b.label: b for b in await mgr.get_blocks()}
    assert "10.0.0.1" in blocks["scratchpad"].value

    await mgr.append_block("scratchpad", "host 10.0.0.2 has http open")
    blocks = {b.label: b for b in await mgr.get_blocks()}
    assert "10.0.0.1" in blocks["scratchpad"].value
    assert "10.0.0.2" in blocks["scratchpad"].value


async def test_record_and_recall_search(tmp_paths, engagement_id):
    mgr = MemoryManager(engagement_id, run_id="r")
    await mgr.initialize()
    await mgr.record("user", "scan the production webserver at 10.1.2.3")
    await mgr.record("assistant", "Running nmap against 10.1.2.3 now")
    await mgr.record("tool", "discovered ssh and apache", tool_name="nmap")

    hits = await mgr.recall_search("apache")
    assert any("apache" in h["content"] for h in hits)


async def test_archival_insert_and_search(tmp_paths, engagement_id):
    mgr = MemoryManager(engagement_id, run_id="r")
    await mgr.initialize()
    await mgr.archival_insert("Critical SQL injection on /search endpoint", source="finding")
    await mgr.archival_insert("Reflected XSS on contact form", source="finding")
    await mgr.archival_insert("Outdated jQuery 1.4 found", source="finding")

    res = await mgr.archival_search("xss vulnerability", k=2)
    assert len(res) == 2
    # With the hash fallback the order isn't semantically meaningful but the
    # texts must all be present and scored.
    assert all("score" in r and "text" in r for r in res)


async def test_builtin_tools_dispatch(tmp_paths, engagement_id):
    mgr = MemoryManager(engagement_id, run_id="r")
    await mgr.initialize()

    out = json.loads(await dispatch_builtin_tool(
        "memory_edit", {"label": "scratchpad", "value": "note 1"}, mgr,
    ))
    assert out["ok"] is True

    out = json.loads(await dispatch_builtin_tool(
        "archival_insert", {"text": "long term note"}, mgr,
    ))
    assert out["ok"] is True
    assert isinstance(out["id"], int)

    out = json.loads(await dispatch_builtin_tool(
        "recall_search", {"query": "scratchpad"}, mgr,
    ))
    # FTS is over messages, scratchpad edit doesn't go there; no hits is OK.
    assert out["ok"] is True

    out = json.loads(await dispatch_builtin_tool(
        "unknown_tool", {}, mgr,
    ))
    assert out["ok"] is False


def test_builtin_tool_names_match_specs():
    from core.memory.tools import builtin_tool_specs

    assert {t["name"] for t in builtin_tool_specs()} == BUILTIN_TOOL_NAMES
    assert "memory_edit" in BUILTIN_TOOL_NAMES
    assert "archival_search" in BUILTIN_TOOL_NAMES


async def test_compaction_when_over_budget(tmp_paths, engagement_id):
    mgr = MemoryManager(
        engagement_id,
        run_id="r",
        summary_trigger_tokens=100,  # tiny budget to force compaction
        keep_recent=2,
    )
    await mgr.initialize()
    big_chunk = "tool produced output. " * 200
    for i in range(8):
        await mgr.record("assistant", f"step {i}")
        await mgr.record("tool", big_chunk, tool_name="nmap")

    msgs = await mgr.build_context(system_prompt="SYS")
    # The system block should have grown to include a recap.
    sys_block = msgs[0]["content"]
    assert "<core_memory>" in sys_block
    # Compaction should have advanced the cursor.
    stats = await mgr.stats()
    assert stats["summary_cursor"] > 0
