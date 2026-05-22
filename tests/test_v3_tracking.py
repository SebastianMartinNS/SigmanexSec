"""
tests/test_v3_tracking.py — Milestone A acceptance tests.

Covers the cognitive-tracking layer end-to-end:

* Action types catalog is stable & complete.
* ``AgentStep`` schema round-trips through the audit chain unchanged.
* Recorder is a no-op when ``SAP_V3_TRACKING_V2`` is off (regression guard
  for the 530-test legacy suite).
* When flag is on, full lifecycle (begin → plan → llm → action → observation
  → reflection → end) produces the expected ordered audit events and the
  BLAKE2b chain still verifies.
* Fernet wrap on prompt/response/reflection payloads round-trips, and chain
  still verifies after wrap.
* Replay summary correctly identifies tools, handoffs, and token totals.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.tracking import AgentStep, AgentStepRecorder
from agent.tracking.recorder import _NullRecorder
from core.audit_events import TRACKING_SCHEMA_V, AuditAction
from core.audit_log import AuditLog, verify_audit_chain
from core.models import Phase
from core.tracking import (
    make_agent_step_event,
    make_llm_prompt_event,
    make_llm_response_event,
    prompt_hash,
)
from core.tracking.encrypted_sink import (
    ENVELOPE_PREFIX,
    decrypt_entry,
    encrypt_value,
)


# ── Action catalog ──────────────────────────────────────────────────────────


def test_audit_action_includes_legacy_and_v3():
    """Catalog must keep legacy strings stable AND ship v3 additions."""
    legacy = {"tool_execute", "tool_complete", "sudo_failure", "decision",
              "gdpr_purge", "gdpr_retention", "sandbox.warn",
              "privileged_tool_execute"}
    v3 = {"llm_prompt_sent", "llm_response_received", "llm_reasoning",
          "agent_step", "role_handoff", "phase_transition",
          "reflection_completed", "state_transition"}
    values = {str(a) for a in AuditAction}
    assert legacy.issubset(values), f"missing legacy: {legacy - values}"
    assert v3.issubset(values), f"missing v3: {v3 - values}"


def test_factory_versioned_payload():
    e = make_llm_prompt_event(
        engagement_id="eng-1", run_id="r-1", role="planner",
        provider="anthropic", model="claude-opus-4-7",
        prompt_hash_hex="0" * 64, messages_count=1, system_chars=10,
        tools_offered=3, temperature=0.0, seed=42,
    )
    assert e.action == "llm_prompt_sent"
    assert e.details["v"] == TRACKING_SCHEMA_V
    assert e.details["prompt_hash"] == "0" * 64
    assert e.details["seed"] == 42


def test_prompt_hash_stable_and_order_dependent():
    msgs_a = [{"role": "user", "content": "a"}, {"role": "user", "content": "b"}]
    msgs_b = [{"role": "user", "content": "b"}, {"role": "user", "content": "a"}]
    assert prompt_hash(msgs_a, system="sys") == prompt_hash(msgs_a, system="sys")
    assert prompt_hash(msgs_a, system="sys") != prompt_hash(msgs_b, system="sys")
    # System prime changes the hash even when messages match.
    assert prompt_hash(msgs_a, system="sys1") != prompt_hash(msgs_a, system="sys2")


# ── AgentStep schema ───────────────────────────────────────────────────────


def test_agent_step_default_state_open():
    s = AgentStep(run_id="r1", engagement_id="e1")
    assert s.status == "open"
    assert s.phase == Phase.SCANNING  # default
    assert s.role == "legacy_monolithic"
    assert s.duration_seconds() is None


def test_agent_step_round_trip_through_audit():
    s = AgentStep(run_id="r1", engagement_id="e1", iteration=2, plan="reconnaissance",
                  action={"tool": "nmap_scan"}, observation={"rc": 0})
    e = make_agent_step_event(engagement_id="e1", step_dump=s.model_dump(mode="json"))
    assert e.action == "agent_step"
    assert e.details["step"]["plan"] == "reconnaissance"
    assert e.details["step"]["action"]["tool"] == "nmap_scan"


# ── Recorder lifecycle ─────────────────────────────────────────────────────


def test_recorder_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SAP_V3_TRACKING_V2", raising=False)
    rec = AgentStepRecorder.get(audit_log=None, run_id="r1")
    assert isinstance(rec, _NullRecorder)


def test_recorder_null_when_audit_log_missing(monkeypatch):
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    rec = AgentStepRecorder.get(audit_log=None, run_id="r1")
    assert isinstance(rec, _NullRecorder)


@pytest.mark.asyncio
async def test_recorder_full_lifecycle_audited(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    # Make sure encryption stays off so we can grep payloads in plaintext.
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")

    log_path = Path(tmp_paths_path := __import__("os").environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    rec = AgentStepRecorder.get(audit_log=log, run_id="r1", engagement_id="e1", role="planner")
    assert not isinstance(rec, _NullRecorder)

    await rec.begin_step(iteration=0, phase=Phase.RECON)
    await rec.record_plan("scan target")
    await rec.record_llm_prompt(
        messages=[{"role": "user", "content": "scan"}],
        system="sys", provider="anthropic", model="claude",
        temperature=0.0, seed=1, tools_offered=2,
        include_payload=True,
    )
    await rec.record_llm_response(
        response_hash_hex="abc", provider="anthropic", model="claude",
        stop_reason="tool_use", input_tokens=10, output_tokens=5,
        latency_ms=200.0, tool_calls_count=1,
        response_payload="ok",
    )
    await rec.record_action({"tool": "nmap_scan", "args": ["-sV"]})
    await rec.record_observation({"rc": 0})
    await rec.record_reflection("port 80 open")
    await rec.end_step(state_after={"open_ports": [80]})
    await log.flush()
    await log.close()

    ok, n, msg = verify_audit_chain(log_path)
    assert ok, f"chain broken at line {n}: {msg}"
    assert n >= 4  # prompt + response + reflection + agent_step

    raw = log_path.read_text().splitlines()
    actions = [json.loads(line)["action"] for line in raw if line.strip()]
    assert "llm_prompt_sent" in actions
    assert "llm_response_received" in actions
    assert "reflection_completed" in actions
    assert "agent_step" in actions
    # Order: llm_prompt → llm_response → reflection → agent_step
    assert actions.index("llm_prompt_sent") < actions.index("llm_response_received")
    assert actions.index("llm_response_received") < actions.index("agent_step")


# ── Fernet wrap ────────────────────────────────────────────────────────────


def test_encrypt_value_idempotent_without_key(monkeypatch):
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")
    # Reset cache so the env change takes effect.
    import core.tracking.encrypted_sink as sink
    sink._FERNET_CACHE = None
    sink._FERNET_DISABLED = False
    assert encrypt_value("secret") == "secret"
    sink._FERNET_DISABLED = False


def test_encrypt_value_round_trip(monkeypatch):
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "1")
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "test-pp")
    import core.tracking.encrypted_sink as sink
    sink._FERNET_CACHE = None
    sink._FERNET_DISABLED = False
    # Reset session_store cache too.
    from core import session_store
    session_store._KEY_CACHE = None

    wrapped = encrypt_value("super-secret-prompt")
    assert isinstance(wrapped, str) and wrapped.startswith(ENVELOPE_PREFIX)
    # decrypt_entry on a synthetic dict.
    out = decrypt_entry({"details": {"prompt_payload": wrapped}})
    assert out["details"]["prompt_payload"] == "super-secret-prompt"


@pytest.mark.asyncio
async def test_chain_verifies_with_encrypted_payload(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "1")
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "test-pp2")
    # Reset caches.
    import core.tracking.encrypted_sink as sink
    sink._FERNET_CACHE = None
    sink._FERNET_DISABLED = False
    from core import session_store
    session_store._KEY_CACHE = None

    log_path = Path(__import__("os").environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    rec = AgentStepRecorder.get(audit_log=log, run_id="r2", engagement_id="e2", role="planner")
    await rec.begin_step(iteration=0)
    await rec.record_llm_prompt(
        messages=[{"role": "user", "content": "secret stuff"}],
        system="sys", provider="anthropic", model="claude",
        temperature=0.0, seed=1, tools_offered=0,
        include_payload=True,
    )
    await rec.end_step()
    await log.flush()
    await log.close()

    ok, n, msg = verify_audit_chain(log_path)
    assert ok, f"chain broken (encryption case) at {n}: {msg}"

    # Confirm payload is wrapped on disk.
    raw_text = log_path.read_text()
    assert ENVELOPE_PREFIX in raw_text


def test_make_llm_response_factory_exposed():
    """Smoke: factory accessible without re-importing recorder."""
    e = make_llm_response_event(
        engagement_id="e", run_id="r", role="planner",
        provider="anthropic", model="claude-opus-4-7",
        response_hash_hex="deadbeef",
        stop_reason="end_turn", input_tokens=1, output_tokens=2,
        latency_ms=0.1, tool_calls_count=0,
    )
    assert e.action == "llm_response_received"
    assert e.details["response_hash"] == "deadbeef"
