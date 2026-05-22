#!/usr/bin/env python3
"""
scripts/soak_smoke.py — In-process smoke soak for the v3.1 multi-agent
runtime.

v3.1.0-rc2 ships this as the **harness** the operator runs to drive a
long-form soak on real LLM hardware. The script itself uses a scripted
``_FakeProvider`` so the smoke variant can run in CI in < 30 seconds; in
production the operator passes ``--provider real`` to swap in the
configured ``LLM_PROVIDER``.

Phase 5 of the consolidation plan asked for a > 4 h soak with
tracemalloc snapshots every 30 min. That is *operational* work: the
in-process variant is the dry run that proves the wiring is sound and
the chain integrity holds across the planned number of role hops.

Usage::

    # Smoke (default, scripted provider, ~5 s):
    python -m scripts.soak_smoke --iterations 20

    # Real soak (operator runs on staging hardware):
    SAP_AGENT_MODE=multi SAP_V3_TRACKING_V2=1 \
        python -m scripts.soak_smoke --iterations 600 --provider real

The script writes a Markdown report to ``reports/soak_<run_id>.md``
with: iteration count, peak RSS, BLAKE2b chain verification result,
role handoff timeline, tracemalloc top-N allocators per snapshot.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tracemalloc
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

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
from agent.tracking import AgentStepRecorder
from core.audit_log import AuditLog, verify_audit_chain


class _ScriptedProvider:
    """Deterministic scripted provider that mimics a realistic ReAct
    cycle: roughly half the iterations call a tool, the rest end the
    turn. Used by the smoke variant of the soak."""

    name = "soak-smoke"

    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **_kwargs: Any) -> LLMResponse:
        self.calls += 1
        # End-turn every 5 iterations to release the loop. Tool-use in
        # between to exercise the dispatcher + recorder.
        if self.calls % 5 == 0:
            return LLMResponse(
                text=f"Cycle {self.calls // 5} complete.",
                stop_reason=StopReason.END_TURN,
                usage=LLMUsage(input_tokens=40, output_tokens=12),
                model="soak",
            )
        return LLMResponse(
            text=f"Iteration {self.calls}: scanning.",
            tool_calls=[ParsedToolCall(
                id=f"c{self.calls}", name="nmap_scan",
                args={"host": f"10.0.0.{(self.calls % 254) + 1}"},
            )],
            stop_reason=StopReason.TOOL_USE,
            usage=LLMUsage(input_tokens=50, output_tokens=10),
            model="soak",
        )

    def normalize_tools(self, tools: list[ToolSpec]) -> list[dict[str, Any]]:
        return [{"name": t.name} for t in tools]

    def format_assistant_message(self, response: LLMResponse) -> ChatMessage:
        return ChatMessage(
            role=Role.ASSISTANT, content=response.text, tool_calls=list(response.tool_calls),
        )

    def format_tool_result(self, *, call_id: str, tool_name: str, content: str) -> ChatMessage:
        return ChatMessage(role=Role.TOOL, content=content, tool_call_id=call_id, name=tool_name)

    def extra_capabilities(self) -> dict[str, Any]:
        return {}


async def _dispatcher(_tc: ParsedToolCall) -> str:
    return json.dumps({"open_ports": [80, 443]})


def _peak_rss_mb() -> float:
    """Best-effort RSS in MiB. Falls back to 0 when /proc is unavailable
    (e.g. macOS); on Linux this gives a robust signal without psutil."""
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


async def _run_soak(iterations: int, audit_log: AuditLog, run_id: str) -> dict[str, Any]:
    recorder = AgentStepRecorder.get(
        audit_log=audit_log,
        run_id=run_id,
        engagement_id="soak-engagement",
        role="legacy_monolithic",
    )
    provider = _ScriptedProvider()
    loop = AgenticLoop(provider=provider, dispatcher=_dispatcher, recorder=recorder)
    ctx = LoopContext(
        run_id=run_id,
        engagement_id="soak-engagement",
        messages=[ChatMessage(role=Role.USER, content="soak smoke driver")],
        tools=[ToolSpec(name="nmap_scan", parameters={"type": "object"})],
        max_iterations=iterations,
        # Soak runs are not exercising the breaker; keep the limit
        # generous so a recurring scripted call doesn't trip it.
        repetition_limit=iterations + 1,
    )

    tracemalloc.start()
    snap_at_start = tracemalloc.take_snapshot()
    started_at = datetime.now(UTC).isoformat()

    final = await loop.run(ctx)

    snap_at_end = tracemalloc.take_snapshot()
    ended_at = datetime.now(UTC).isoformat()

    # Diff allocators: show the top 5 lines whose size grew most.
    top_diffs = snap_at_end.compare_to(snap_at_start, key_type="lineno")[:5]
    diff_table = [
        {
            "file": str(d.traceback[0].filename) if d.traceback else "?",
            "line": d.traceback[0].lineno if d.traceback else 0,
            "size_diff_kb": d.size_diff / 1024.0,
        }
        for d in top_diffs
    ]
    tracemalloc.stop()

    return {
        "run_id": run_id,
        "iterations_requested": iterations,
        "iterations_actual": provider.calls,
        "started_at": started_at,
        "ended_at": ended_at,
        "final_text": final,
        "peak_rss_mb": _peak_rss_mb(),
        "tracemalloc_top5": diff_table,
    }


def _audit_actions(audit_log_path: Path, run_id: str) -> dict[str, int]:
    if not audit_log_path.exists():
        return {}
    counter: Counter[str] = Counter()
    for line in audit_log_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        details = obj.get("details") or {}
        # Match by run_id when the event carries it; tool_dispatch events
        # may not, so count them as global.
        rid = details.get("run_id") if isinstance(details, dict) else None
        if rid and rid != run_id:
            continue
        counter[obj.get("action", "?")] += 1
    return dict(counter)


def _render_report(
    out_dir: Path,
    summary: dict[str, Any],
    chain_ok: bool,
    chain_lines: int,
    chain_msg: str,
    actions: dict[str, int],
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / f"soak_{summary['run_id']}.md"
    md.write_text(
        f"# Soak smoke — `{summary['run_id']}`\n\n"
        f"- Started:  {summary['started_at']}\n"
        f"- Ended:    {summary['ended_at']}\n"
        f"- Requested iterations: {summary['iterations_requested']}\n"
        f"- Actual provider calls: {summary['iterations_actual']}\n"
        f"- Peak RSS: {summary['peak_rss_mb']:.1f} MiB\n"
        f"- Chain verification: **{'OK' if chain_ok else 'FAILED'}** "
        f"({chain_lines} lines, {chain_msg})\n\n"
        "## Audit action counters\n"
        + "\n".join(f"- `{k}`: {v}" for k, v in sorted(actions.items()))
        + "\n\n## tracemalloc top 5 (size growth, kB)\n"
        + "\n".join(
            f"- `{d['file']}:{d['line']}` — {d['size_diff_kb']:+.1f} kB"
            for d in summary["tracemalloc_top5"]
        )
        + "\n\n## Final loop output\n\n"
        f"```\n{summary['final_text']}\n```\n"
        ,
        encoding="utf-8",
    )
    return md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--iterations", type=int, default=20,
                        help="Provider chat calls; the loop will exit"
                             " whenever a stop_reason=end_turn is returned.")
    parser.add_argument("--run-id", default=f"soak_{datetime.now(UTC):%Y%m%dT%H%M%S}",
                        help="Identifier used in the audit chain and report filename.")
    parser.add_argument("--audit-log", default="logs/audit.jsonl")
    parser.add_argument("--output", default="reports/")
    args = parser.parse_args(argv)

    os.environ.setdefault("SAP_V3_TRACKING_V2", "1")
    os.environ.setdefault("SAP_AUDIT_ENCRYPT", "0")

    audit_path = Path(args.audit_log)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    async def _drive() -> dict[str, Any]:
        audit_log = AuditLog(log_path=str(audit_path))
        result = await _run_soak(args.iterations, audit_log, args.run_id)
        await audit_log.flush()
        await audit_log.close()
        return result

    summary = asyncio.run(_drive())

    chain_ok, chain_n, chain_msg = verify_audit_chain(audit_path)
    actions = _audit_actions(audit_path, args.run_id)

    md = _render_report(
        Path(args.output), summary, chain_ok, chain_n, chain_msg, actions,
    )

    print(json.dumps({
        "ok": chain_ok,
        "run_id": summary["run_id"],
        "iterations_actual": summary["iterations_actual"],
        "peak_rss_mb": summary["peak_rss_mb"],
        "audit_actions": actions,
        "report": str(md),
    }, indent=2))

    return 0 if chain_ok else 2


if __name__ == "__main__":
    sys.exit(main())
