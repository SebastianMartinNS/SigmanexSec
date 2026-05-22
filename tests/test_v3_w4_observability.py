"""
tests/test_v3_w4_observability.py — Settimana 4 acceptance.

Pins the v3.1 W4 observability gates:

* **S2** — the dashboard exposes a Prometheus exposition at
  ``GET /metrics``; without the optional ``[observability]`` extra
  installed the endpoint still answers with a clear "metrics disabled"
  marker (never 500); with the extra installed it answers with the
  canonical text/plain content-type.
* **S4** — ``scripts/replay_run.py`` ingests a recorded audit chain
  written by :class:`AgentStepRecorder` (W2 wiring) and produces a JSONL
  + Markdown report; the BLAKE2b chain verifies and the action counters
  in the summary match what the recorder emitted.

Both tests run in-process with a scripted ``_FakeProvider`` so no LLM
is required and no extra deps must be installed at CI time.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from agent.loop import AgenticLoop, LoopContext
from agent.providers.types import (
    ChatMessage,
    LLMResponse,
    LLMUsage,
    ParsedToolCall,
    Role,
    StopReason,
    ToolSpec,
)
from agent.tracking.recorder import AgentStepRecorder
from core.audit_log import AuditLog

# ── Tiny LLMProvider stub ─────────────────────────────────────────────────


class _FakeProvider:
    name = "fake-w4"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        if self.calls == 1:
            return LLMResponse(
                text="Scanning the lab subnet.",
                tool_calls=[ParsedToolCall(
                    id="call_1", name="nmap_scan", args={"host": "10.0.0.1"},
                )],
                stop_reason=StopReason.TOOL_USE,
                usage=LLMUsage(input_tokens=100, output_tokens=20),
                model="fake",
            )
        return LLMResponse(
            text="Found port 80 open. Engagement done.",
            stop_reason=StopReason.END_TURN,
            usage=LLMUsage(input_tokens=120, output_tokens=15),
            model="fake",
        )

    def normalize_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        return [{"name": t.name} for t in tools]

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        return ChatMessage(
            role=Role.ASSISTANT, content=response.text, tool_calls=list(response.tool_calls),
        )

    def format_tool_result(self, *, call_id: str, tool_name: str, content: str) -> ChatMessage:
        return ChatMessage(
            role=Role.TOOL, content=content, tool_call_id=call_id, name=tool_name,
        )

    def extra_capabilities(self) -> dict[str, Any]:
        return {}


# ── S2: /metrics endpoint ─────────────────────────────────────────────────


def test_metrics_endpoint_responds(monkeypatch):
    """The /metrics route must always respond (200) — never 500. When
    prometheus_client is not installed it returns the documented
    'metrics disabled' marker; when installed it returns the
    canonical text/plain content type.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from sap_dashboard.backend.routes.health import router
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text
    content_type = resp.headers.get("content-type", "")
    if "metrics disabled" in body:
        # The no-op path (prometheus_client absent or SAP_METRICS_ENABLED=0).
        assert content_type.startswith("text/plain")
    else:
        # The Prometheus exposition path.
        assert content_type.startswith("text/plain")
        # ``# HELP`` is the first line of every Prometheus metric family.
        assert "# HELP" in body or "# TYPE" in body or body == ""


def test_metrics_endpoint_documents_disabled_when_extra_missing(monkeypatch):
    """When the operator explicitly disables metrics, the endpoint must
    still answer 200 with the documented marker (never 500)."""
    monkeypatch.setenv("SAP_METRICS_ENABLED", "0")
    # Reset the cached registry so the env change is honoured.
    import core.observability.metrics as m
    m._REGISTRY_CACHE = None

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from sap_dashboard.backend.routes.health import router
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "metrics disabled" in resp.text
    # Reset cache for downstream tests.
    m._REGISTRY_CACHE = None


def test_metrics_registry_lazy_singleton(monkeypatch):
    """:func:`core.observability.get_metrics` must materialize once and
    return the same instance on subsequent calls — counters/gauges keep
    state across the process."""
    import core.observability.metrics as m
    m._REGISTRY_CACHE = None
    first = m.get_metrics()
    second = m.get_metrics()
    assert first is second


# ── S4: replay_run.py ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_replay_run_smoke_on_recorded_engagement(tmp_paths, monkeypatch):
    """End-to-end smoke for ``scripts/replay_run.py``:

    1. drive a short AgenticLoop run with the cognitive recorder ON so
       the audit chain contains the v3 action types,
    2. invoke the replay script as a subprocess against that audit log,
    3. assert the chain verifies, the action counters match what the
       recorder emitted, and the Markdown + JSONL reports are written.
    """
    monkeypatch.setenv("SAP_V3_TRACKING_V2", "1")
    monkeypatch.setenv("SAP_AUDIT_ENCRYPT", "0")  # plaintext payloads to grep

    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    log = AuditLog(log_path=str(log_path))
    recorder = AgentStepRecorder.get(
        audit_log=log, run_id="run_replay_w4",
        engagement_id="eng-replay-w4", role="legacy_monolithic",
    )
    provider = _FakeProvider()

    async def dispatcher(_tc: ParsedToolCall) -> str:
        return json.dumps({"open_ports": [80]})

    loop = AgenticLoop(provider=provider, dispatcher=dispatcher, recorder=recorder)
    ctx = LoopContext(
        run_id="run_replay_w4",
        engagement_id="eng-replay-w4",
        messages=[ChatMessage(role=Role.USER, content="scan the lab")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=5,
    )
    await loop.run(ctx)
    await log.flush()
    await log.close()

    # Sanity: the recorder produced the expected v3 events before we
    # hand the chain to the replay script.
    actions_before = Counter(
        json.loads(line)["action"]
        for line in log_path.read_text().splitlines()
        if line.strip()
    )
    assert actions_before["agent_step"] == 2
    assert actions_before["llm_prompt_sent"] == 2
    assert actions_before["llm_response_received"] == 2

    # Invoke the script as a subprocess so we exercise the full CLI
    # surface (argparse + subprocess invariants), not just the helper
    # functions.
    out_dir = Path(os.environ["SAP_SESSIONS_DIR"]) / "replays"
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            sys.executable, "scripts/replay_run.py",
            "--run-id", "run_replay_w4",
            "--audit-log", str(log_path),
            "--output", str(out_dir),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"replay_run.py exit {result.returncode}; stderr={result.stderr}"
    )

    summary = json.loads(result.stdout.split("\n[replay]")[0])
    assert summary["chain_verified"] is True
    assert summary["agent_steps"] == 2
    assert summary["actions"]["llm_prompt_sent"] == 2
    assert summary["actions"]["llm_response_received"] == 2

    # The script must produce both report flavours.
    jsonl = out_dir / "run_replay_w4.jsonl"
    md = out_dir / "run_replay_w4.md"
    assert jsonl.is_file()
    assert md.is_file()
    md_body = md.read_text()
    assert "Replay report" in md_body
    assert "run_replay_w4" in md_body


def test_replay_run_exits_3_when_run_id_unknown(tmp_paths):
    """Documents the public CLI contract: an unknown run_id returns
    exit code 3 (no events found) without crashing."""
    log_path = Path(os.environ["AUDIT_LOG_PATH"])
    # Write nothing so the audit file does not exist either.
    repo_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            sys.executable, "scripts/replay_run.py",
            "--run-id", "definitely-not-a-run-id",
            "--audit-log", str(log_path),
            "--output", str(Path(os.environ["SAP_SESSIONS_DIR"]) / "replays"),
        ],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 3, (
        f"expected exit 3 for unknown run_id; got {result.returncode}; "
        f"stderr={result.stderr}"
    )
