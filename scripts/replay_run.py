#!/usr/bin/env python3
"""
scripts/replay_run.py — Replay a single orchestrator run from the audit chain.

v3.0.0 ships a *passive* replay: the script reads ``logs/audit.jsonl``, filters
events to one ``run_id``, decrypts the Fernet-wrapped fields (when the operator
provides the key), verifies the BLAKE2b hash chain, and produces a normalized
JSONL report at ``sessions/replays/<run_id>.jsonl`` plus a one-page Markdown
summary at ``sessions/replays/<run_id>.md``.

This is enough for compliance reviewers (was every LLM call audited? what did
the model decide? which tools fired?) and is the foundation for *active*
deterministic replay landing in v3.1 once the provider abstraction (Milestone
B) carries through ``llm_seed`` end-to-end.

Usage::

    python -m scripts.replay_run --run-id run_abc123def4 \\
        --audit-log logs/audit.jsonl \\
        --output sessions/replays/

Exit codes::

    0 — replay produced; chain verified
    1 — bad arguments
    2 — chain verification failed (will still write a partial report)
    3 — no events found for the requested run_id

The script is intentionally dependency-free (stdlib + the project's own
``core.tracking.encrypted_sink``) so it can run inside a stripped-down
forensic container.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from core.audit_events import AuditAction  # noqa: E402
from core.audit_log import verify_audit_chain  # noqa: E402
from core.tracking.encrypted_sink import decrypt_entry  # noqa: E402

# Action types that carry useful timeline information for a replay report.
_TIMELINE_ACTIONS = {
    str(a)
    for a in (
        AuditAction.LLM_PROMPT_SENT,
        AuditAction.LLM_RESPONSE_RECEIVED,
        AuditAction.LLM_REASONING,
        AuditAction.AGENT_STEP,
        AuditAction.ROLE_HANDOFF,
        AuditAction.PHASE_TRANSITION,
        AuditAction.REFLECTION_COMPLETED,
        AuditAction.STATE_TRANSITION,
        AuditAction.TOOL_EXECUTE,
        AuditAction.TOOL_COMPLETE,
        AuditAction.SUDO_FAILURE,
        AuditAction.SANDBOX_WARN,
    )
}


def _event_run_id(obj: dict[str, Any]) -> str:
    """Best-effort extraction of run_id from any entry shape."""
    details = obj.get("details") or {}
    if isinstance(details, dict):
        rid = details.get("run_id")
        if isinstance(rid, str) and rid:
            return rid
        step = details.get("step")
        if isinstance(step, dict):
            rid = step.get("run_id")
            if isinstance(rid, str) and rid:
                return rid
    return ""


def collect_events(audit_path: Path, run_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not audit_path.exists():
        return out
    with open(audit_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if _event_run_id(obj) != run_id:
                continue
            obj.pop("_prev", None)
            obj.pop("_hash", None)
            out.append(decrypt_entry(obj))
    return out


def _summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    actions = Counter(e.get("action", "") for e in events)
    roles = Counter()
    phases = Counter()
    tools: list[str] = []
    handoffs: list[tuple[str, str]] = []
    step_count = 0
    total_in_tokens = 0
    total_out_tokens = 0
    for e in events:
        details = e.get("details") or {}
        role = details.get("role") or ""
        if role:
            roles[role] += 1
        if e.get("action") == str(AuditAction.AGENT_STEP):
            step_count += 1
            step = details.get("step") or {}
            phases[step.get("phase", "")] += 1
            total_in_tokens += int(step.get("input_tokens", 0) or 0)
            total_out_tokens += int(step.get("output_tokens", 0) or 0)
            action = step.get("action") or {}
            tool = action.get("tool") or action.get("name")
            if tool:
                tools.append(tool)
        elif e.get("action") == str(AuditAction.ROLE_HANDOFF):
            handoffs.append((details.get("src_role", "?"), details.get("dst_role", "?")))
    return {
        "event_count": len(events),
        "actions": dict(actions),
        "roles": dict(roles),
        "phases": dict(phases),
        "agent_steps": step_count,
        "input_tokens_total": total_in_tokens,
        "output_tokens_total": total_out_tokens,
        "tools_invoked": tools,
        "handoffs": handoffs,
    }


def _render_markdown(run_id: str, summary: dict[str, Any], chain_ok: bool, chain_msg: str) -> str:
    lines: list[str] = []
    lines.append(f"# Replay report — run `{run_id}`\n")
    lines.append(f"- **Chain verification**: {'OK' if chain_ok else 'FAILED'} ({chain_msg})")
    lines.append(f"- **Events**: {summary['event_count']}")
    lines.append(f"- **Agent steps**: {summary['agent_steps']}")
    lines.append(
        f"- **Tokens**: in={summary['input_tokens_total']} "
        f"out={summary['output_tokens_total']}"
    )
    lines.append("")
    lines.append("## Action counts")
    for k, v in sorted(summary["actions"].items(), key=lambda kv: -kv[1]):
        lines.append(f"- `{k}` × {v}")
    lines.append("")
    if summary["roles"]:
        lines.append("## Roles seen")
        for k, v in summary["roles"].items():
            lines.append(f"- `{k}` × {v}")
        lines.append("")
    if summary["handoffs"]:
        lines.append("## Role handoffs")
        for src, dst in summary["handoffs"]:
            lines.append(f"- `{src}` → `{dst}`")
        lines.append("")
    if summary["tools_invoked"]:
        lines.append("## Tools invoked (in order)")
        for t in summary["tools_invoked"]:
            lines.append(f"1. `{t}`")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay an orchestrator run from audit logs")
    parser.add_argument("--run-id", required=True, help="run_id to replay")
    parser.add_argument(
        "--audit-log",
        default="logs/audit.jsonl",
        help="Path to audit log JSONL (default: logs/audit.jsonl)",
    )
    parser.add_argument(
        "--output",
        default="sessions/replays/",
        help="Directory to write the replay report (default: sessions/replays/)",
    )
    parser.add_argument(
        "--include-payload",
        action="store_true",
        help="Include decrypted prompt/response bodies in the JSONL output",
    )
    args = parser.parse_args(argv)

    audit_path = Path(args.audit_log)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    chain_ok, chain_n, chain_msg = verify_audit_chain(audit_path)

    events = collect_events(audit_path, args.run_id)
    if not events:
        print(f"[replay] no events found for run_id={args.run_id}", file=sys.stderr)
        return 3

    if not args.include_payload:
        for e in events:
            d = e.get("details") or {}
            for sensitive in ("prompt_payload", "response_payload", "reasoning_text", "reflection_text"):
                d.pop(sensitive, None)

    jsonl_path = out_dir / f"{args.run_id}.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for e in events:
            if e.get("action") in _TIMELINE_ACTIONS or True:  # keep everything
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

    summary = _summarize(events)
    summary["chain_verified"] = chain_ok
    summary["chain_check_lines"] = chain_n
    summary["chain_check_message"] = chain_msg

    md_path = out_dir / f"{args.run_id}.md"
    md_path.write_text(_render_markdown(args.run_id, summary, chain_ok, chain_msg), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n[replay] events  → {jsonl_path}")
    print(f"[replay] summary → {md_path}")

    if not chain_ok:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
