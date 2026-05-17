"""
mcp_servers/_response.py — Standard response shape for MCP tools.

Every tool that returns the output of an ``ExecutionResult`` should funnel
through ``build_tool_response``. The shape is configurable per tool via a
``response_profile``; the available profiles are:

============= =============================================================
``full``      Whole stdout (subject only to the executor's in-memory cap),
              suitable for tools whose output is small and structurally
              important (e.g. ``hashid -j``).
``head_tail`` Default for recon/exploit tools: head + tail snippet plus the
              canonical ``output_ref`` for on-demand recall.
``ref_only``  No inline output; the caller MUST follow ``output_ref`` via
              MCP ``resources/read`` to retrieve content. Cheapest in token
              budget.
``summary_only`` Only the parsed structured summary is returned (no raw
              output). For tools whose stdout is purely noise once parsed.
============= =============================================================

The helper additionally always exposes:
  - ``call_id``           — correlation id (also in audit log).
  - ``output_ref``        — { stdout_uri, stderr_uri, artifacts_uri }.
  - ``full_size_bytes``   — { stdout, stderr } pre-cap byte counts.
  - ``returncode`` / ``duration_seconds``.

Per-tool overrides are looked up by tool/MCP-tool name from
``parrot_tools.yaml`` (response_profile + head/tail bytes).
"""
# NB: do NOT use ``from __future__ import annotations`` here. FastMCP introspects
# tool parameter annotations at registration time via ``issubclass`` and chokes
# on stringified annotations (PEP 563).
import os
import re
from typing import Any

from core.models import ExecutionResult

# Default head/tail allocations (bytes, applied to the in-memory string).
_DEFAULT_HEAD_BYTES = 8192
_DEFAULT_TAIL_BYTES = 2048
_VALID_PROFILES = {"full", "head_tail", "ref_only", "summary_only"}


# ─────────────────────────────────────────────
# Hard caps (defence-in-depth — see plan: prompt-explosion 2026-04-30)
# ─────────────────────────────────────────────
# These caps are *enforced* on top of any per-tool override coming from
# parrot_tools.yaml. The previous design trusted descriptors blindly, so a
# typo (or a future tool with response_head_bytes=10_000_000) could ship a
# 10 MB inline payload to the LLM. The agent-side pre-flight guard exists
# but the server-side hard-cap closes the loophole closer to the source.
# Override via SAP_MCP_HARD_CAP_BYTES if needed.


def _hard_cap_bytes() -> int:
    try:
        v = int(os.environ.get("SAP_MCP_HARD_CAP_BYTES", "32768"))
    except (TypeError, ValueError):
        v = 32768
    return max(1024, v)  # never let an env-typo disable the cap entirely


def _recall_cap_bytes() -> int:
    try:
        v = int(os.environ.get("SAP_MCP_RECALL_CAP_BYTES", "65536"))
    except (TypeError, ValueError):
        v = 65536
    return max(_hard_cap_bytes(), v)


# ─────────────────────────────────────────────
# Empty-output diagnosis (Phase 2)
# ─────────────────────────────────────────────
# When a tool returns rc=0 and no stdout, the agent has no signal to act on
# and is liable to retry with permuted arguments (loop). We surface a
# structured ``diagnosis`` field by pattern-matching stderr against known
# failure modes. Order matters: first hit wins, so list specific causes
# (unreachable network) before generic ones (no findings).
_EMPTY_DIAGNOSIS_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("no_templates", re.compile(
        r"(no templates (were |found)|0 templates were loaded|"
        r"could not find templates)", re.I)),
    ("host_unreachable", re.compile(
        r"(connection refused|no route to host|network is unreachable|"
        r"could not resolve host|name or service not known|"
        r"unable to connect|dial tcp \S+: i/o timeout|"
        r"failed to connect)", re.I)),
    ("tls_handshake_failed", re.compile(
        r"(tls .{0,30}handshake|certificate verify failed|"
        r"x509: |ssl.*handshake|sslv3 alert|tls.*alert)", re.I)),
    ("timeout_in_tool", re.compile(
        r"(deadline exceeded|context deadline|operation timed out|"
        r"i/o timeout)", re.I)),
    ("rate_limited_upstream", re.compile(
        r"(429 too many requests|rate ?limit(ed)?|throttled)", re.I)),
)


def diagnose_empty_output(result: ExecutionResult) -> dict[str, str] | None:
    """Classify why a tool produced no stdout despite rc=0.

    Returns a ``{kind, evidence}`` dict, or ``None`` when the result has
    actual stdout content. Never raises.
    """
    try:
        if result.returncode != 0:
            return None
        if (result.stdout or "").strip():
            return None
        stderr = result.stderr or ""
        for kind, rx in _EMPTY_DIAGNOSIS_PATTERNS:
            m = rx.search(stderr)
            if m:
                # Evidence: line containing the match, capped at 200 chars.
                start = stderr.rfind("\n", 0, m.start()) + 1
                end = stderr.find("\n", m.end())
                if end == -1:
                    end = len(stderr)
                line = stderr[start:end].strip()[:200]
                return {"kind": kind, "evidence": line}
        # rc=0, empty stdout, no recognised stderr: ambiguous.
        return {
            "kind": "no_findings" if not stderr.strip() else "unknown_empty",
            "evidence": stderr.strip()[:200],
        }
    except Exception:  # pragma: no cover - defensive
        return None


def _slice_head_tail(
    text: str,
    head_bytes: int,
    tail_bytes: int,
) -> tuple[str, str | None]:
    """Return (head, tail) — tail is None when text fits entirely in head."""
    if not text:
        return "", None
    if len(text) <= head_bytes:
        return text, None
    head = text[:head_bytes]
    if tail_bytes <= 0:
        return head, None
    return head, text[-tail_bytes:]


def build_tool_response(
    result: ExecutionResult,
    *,
    summary: dict[str, Any] | None = None,
    profile: str = "head_tail",
    head_bytes: int = _DEFAULT_HEAD_BYTES,
    tail_bytes: int = _DEFAULT_TAIL_BYTES,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical MCP tool response.

    ``summary`` is merged into the top-level response (parsed key fields
    such as ``credentials_found``, ``vulnerable``, ``hashes`` …).
    ``extra`` is merged last and can override anything for niche tools.
    """
    if profile not in _VALID_PROFILES:
        profile = "head_tail"

    # Hard-cap defence: clamp head/tail regardless of caller intent. We can
    # still ship the full data via output_ref → read_tool_output(head=N).
    cap = _hard_cap_bytes()
    head_clamped = min(max(0, head_bytes), cap)
    tail_budget = max(0, cap - head_clamped)
    tail_clamped = min(max(0, tail_bytes), tail_budget)
    cap_enforced = (head_clamped != head_bytes) or (tail_clamped != tail_bytes)

    response: dict[str, Any] = {
        "call_id": result.call_id,
        "run_id": result.run_id,
        "tool": result.tool,
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
        "truncated_in_memory": bool(result.truncated),
        "full_size_bytes": {
            "stdout": result.stdout_bytes_full,
            "stderr": result.stderr_bytes_full,
        },
    }

    if result.output_ref is not None:
        response["output_ref"] = {
            "stdout_uri": result.output_ref.stdout_uri,
            "stderr_uri": result.output_ref.stderr_uri,
            "artifacts_uri": result.output_ref.artifacts_uri,
        }

    if summary:
        response.update(summary)

    if profile == "summary_only":
        # No raw output at all.
        pass
    elif profile == "ref_only":
        response["output"] = None
    elif profile == "full":
        # "full" still respects the hard cap to prevent prompt-explosion.
        out = result.stdout or ""
        if len(out) > cap:
            response["output"] = out[:cap]
            response["truncation_enforced"] = True
            cap_enforced = True
        else:
            response["output"] = out
        if result.stderr:
            err = result.stderr
            if len(err) > cap:
                response["stderr"] = err[:cap]
                cap_enforced = True
            else:
                response["stderr"] = err
    else:  # head_tail
        head, tail = _slice_head_tail(result.stdout, head_clamped, tail_clamped)
        response["stdout_head"] = head
        if tail is not None:
            response["stdout_tail"] = tail
        # stderr is usually short; include head only (clamped).
        if result.stderr:
            err_head, _ = _slice_head_tail(result.stderr, head_clamped, 0)
            response["stderr_head"] = err_head

    if cap_enforced:
        response.setdefault("truncation_enforced", True)

    # Phase 2: surface a structured diagnosis when a scanner returned no
    # output. Without this the agent has no signal and is likely to retry
    # with permuted arguments (severity, scheme), tripping the loop.
    # Caller can override by pre-populating ``diagnosis`` in ``extra``.
    if "diagnosis" not in (extra or {}):
        diag = diagnose_empty_output(result)
        if diag is not None:
            response["diagnosis"] = diag

    if extra:
        response.update(extra)
    return response


def register_resource_handlers(mcp, store_getter, server_suffix: str = "") -> None:
    """Expose ``sap://run/{run_id}/output/{call_id}/{kind}`` via FastMCP.

    ``store_getter`` is a zero-arg callable returning a ToolOutputStore. The
    handler supports ``head``/``tail``/``offset``/``length`` query semantics
    via per-resource convenience tool functions.

    ``server_suffix`` (e.g. ``"engagement"``, ``"recon"``) makes the registered
    tool name unique across MCP servers — the WebUI MCP store deduplicates by
    name, so without a suffix only one of the 6 ``read_tool_output`` tools
    would survive (see [MCPStore] Tool name conflict warnings).
    """

    tool_name = f"read_tool_output_{server_suffix}" if server_suffix else "read_tool_output"

    @mcp.tool(name=tool_name)
    async def read_tool_output(
        call_id: str,
        kind: str = "stdout",
        head: int = 0,
        tail: int = 0,
        offset: int = 0,
        length: int = 0,
    ) -> dict:
        """Read bytes from a previously persisted tool output.

        Use this when a prior tool call returned ``head_tail`` or ``ref_only``
        and you need more of the original output (e.g., a specific section
        identified by line number, or the full stderr for diagnostics).

        Args:
            call_id: id returned by a previous tool invocation
            kind: "stdout" or "stderr"
            head: return first N bytes (0 = ignore)
            tail: return last N bytes (0 = ignore)
            offset/length: arbitrary range read (0/0 = ignore)
        """
        # Clamp every read range to the recall cap. Callers can paginate via
        # offset/length if they really need more bytes; a single response is
        # never allowed to ship an unbounded payload to the LLM.
        rcap = _recall_cap_bytes()
        head_c = min(max(0, int(head)), rcap) if head else 0
        tail_c = min(max(0, int(tail)), rcap) if tail else 0
        length_c = min(max(0, int(length)), rcap) if length else 0
        offset_c = max(0, int(offset)) if offset else 0
        # Ensure at least one read mode is selected; default to head=rcap.
        if not (head_c or tail_c or length_c):
            head_c = rcap
        store = store_getter()
        try:
            data = await store.read(
                call_id, kind=kind,
                head=head_c or None,
                tail=tail_c or None,
                offset=offset_c or None,
                length=length_c or None,
            )
        except KeyError:
            return {"error": "call_id not found", "call_id": call_id}
        ref = await store.get(call_id)
        # Final defence-in-depth slice: even if the store mis-honours the
        # request bounds (or if a caller bypassed clamping by passing both
        # head and length), never ship more than the recall cap.
        if len(data) > rcap:
            data = data[:rcap]
        return {
            "call_id": call_id,
            "kind": kind,
            "bytes_returned": len(data),
            "total_bytes": (
                ref.stdout_bytes if (ref and kind == "stdout")
                else ref.stderr_bytes if ref else 0
            ),
            "content": data.decode("utf-8", errors="replace"),
            "recall_cap_bytes": rcap,
        }

    return read_tool_output


def register_run_context_tool(mcp, executor, server_suffix: str = ""):
    """Expose ``set_run_context_{suffix}`` so the orchestrator can bind the
    server-side ``ToolExecutor`` to a specific ``run_id``.

    Without this binding ``ToolOutputStore.put`` is short-circuited (run_id
    is empty), spill-to-disk is OFF and ``read_tool_output_*`` returns
    ``call_id not found``. Calling this once at the beginning of a run
    re-enables persistence (see plan 2026-04-30, Fase 3.1).
    """
    tool_name = f"set_run_context_{server_suffix}" if server_suffix else "set_run_context"

    @mcp.tool(name=tool_name)
    async def set_run_context(run_id: str, engagement_id: str = "") -> dict:
        """Bind this MCP server's executor to a specific run_id for output persistence.

        Args:
            run_id: opaque identifier shared with the orchestrator's audit log
            engagement_id: optional, currently informational (the executor
                receives engagement_id per ``run`` call already)
        """
        try:
            executor.set_run_id(run_id or "")
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {
            "ok": True,
            "run_id": run_id,
            "engagement_id": engagement_id,
            "server": server_suffix or "default",
        }

    return set_run_context
