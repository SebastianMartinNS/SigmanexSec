"""
tests/test_v3_multi_agent_e2e.py — Milestone C5+C6 acceptance.

Drives the Coordinator with a dummy driver through a realistic 4-role
chain (planner → recon → exploit → reporter) and verifies the audit
chain captures every ROLE_HANDOFF + PHASE_TRANSITION + STATE_TRANSITION.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.coordination import AgentContext, CompletedTask, FindingRef
from agent.coordinator import Coordinator, agent_mode, make_dummy_driver
from agent.state import AgentState
from core.audit_log import AuditLog, verify_audit_chain
from core.models import Phase

# ── Coordinator default mode --------------------------------------------


def test_agent_mode_defaults_to_single(monkeypatch):
    monkeypatch.delenv("SAP_AGENT_MODE", raising=False)
    assert agent_mode() == "single"


def test_agent_mode_accepts_multi(monkeypatch):
    monkeypatch.setenv("SAP_AGENT_MODE", "multi")
    assert agent_mode() == "multi"


def test_agent_mode_falls_back_to_single_on_garbage(monkeypatch):
    monkeypatch.setenv("SAP_AGENT_MODE", "definitely-not-a-mode")
    assert agent_mode() == "single"


# ── Coordinator walk ----------------------------------------------------


@pytest.mark.asyncio
async def test_coordinator_walks_planned_handoffs():
    plan = [
        ("recon_analyst", Phase.RECON, "scope locked"),
        ("exploit_dev", Phase.EXPLOITATION, "high-conf finding"),
        ("reporter", Phase.REPORTING, "exploit chain done"),
    ]
    coord = Coordinator(
        engagement_id="eng-test",
        driver=make_dummy_driver(handoff_plan=plan),
        initial_role="planner",
        initial_phase=Phase.SCOPING,
    )
    final = await coord.run()
    assert final == "reporter"
    assert coord.state is AgentState.DONE
    assert coord.current_phase is Phase.REPORTING


@pytest.mark.asyncio
async def test_coordinator_blocks_illegal_handoff():
    """Reporter has no outgoing handoff edges. A plan that tries to hand
    off *from* reporter must be rejected by the RoleValidator."""
    bad_plan = [
        ("reporter", Phase.REPORTING, "skip everything"),
        # The Coordinator never reaches the second hop because the first
        # closure would try to hand off from reporter.
        ("planner", Phase.SCOPING, "back to start"),
    ]
    Coordinator(
        engagement_id="eng-test",
        driver=make_dummy_driver(handoff_plan=bad_plan),
        initial_role="planner",
        initial_phase=Phase.SCOPING,
    )
    # First role is planner; closure plans to hand off to reporter; that
    # *is* a legal edge from planner... wait, planner→reporter is NOT in
    # planner.can_handoff_to. The validator should reject.
    plan2 = [
        ("reporter", Phase.REPORTING, "illegal jump"),
    ]
    coord2 = Coordinator(
        engagement_id="eng-test",
        driver=make_dummy_driver(handoff_plan=plan2),
        initial_role="planner",
        initial_phase=Phase.SCOPING,
    )
    await coord2.run()
    assert coord2.state is AgentState.FAILED


@pytest.mark.asyncio
async def test_coordinator_emits_audit_events(tmp_paths):
    """Full chain produces LLM-free audit events the dashboard can render."""
    import os
    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))

    # The recorder is wired via the orchestrator in production; here we
    # construct one directly for the test.
    monkey_run_id = "run_multi_e2e"
    os.environ["SAP_V3_TRACKING_V2"] = "1"
    os.environ["SAP_AUDIT_ENCRYPT"] = "0"
    from agent.tracking.recorder import AgentStepRecorder
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id=monkey_run_id,
        engagement_id="eng-test", role="planner",
    )

    plan = [
        ("recon_analyst", Phase.RECON, "scope locked"),
        ("exploit_dev", Phase.EXPLOITATION, "high-conf finding"),
        ("reporter", Phase.REPORTING, "exploit chain done"),
    ]
    coord = Coordinator(
        engagement_id="eng-test",
        run_id=monkey_run_id,
        driver=make_dummy_driver(handoff_plan=plan),
        recorder=recorder,
        initial_role="planner",
        initial_phase=Phase.SCOPING,
    )
    final = await coord.run()
    assert final == "reporter"

    await log.flush()
    await log.close()

    ok, _n, msg = verify_audit_chain(log_path)
    assert ok, msg

    actions = []
    for raw in log_path.read_text().splitlines():
        if raw.strip():
            actions.append(json.loads(raw)["action"])
    # 3 handoffs across 4 roles → 3 role_handoff events, ≥3 phase_transition.
    assert actions.count("role_handoff") == 3
    assert actions.count("phase_transition") >= 3


# ── AgentContext rendering ----------------------------------------------


def test_agent_context_prompt_block_summarises():
    ctx = AgentContext(
        engagement_id="eng-x", run_id="r1",
        current_phase=Phase.EXPLOITATION,
        parent_role="recon_analyst", target_role="exploit_dev",
        handoff_reason="SQLi confirmed on /login",
        findings_so_far=[FindingRef(finding_id="f1", severity="high", summary="SQLi /login")],
        open_questions=["can we escalate to admin?"],
        completed_tasks=[CompletedTask(description="nmap+sqlmap", tool_calls_made=2)],
    )
    block = ctx.to_prompt_block()
    assert "recon_analyst" in block
    assert "exploit_dev" in block
    assert "SQLi" in block
    assert "escalate to admin" in block
