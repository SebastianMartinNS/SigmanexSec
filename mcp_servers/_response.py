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
from typing import Any, Optional

from core.models import ExecutionResult


# Default head/tail allocations (bytes, applied to the in-memory string).
_DEFAULT_HEAD_BYTES = 8192
_DEFAULT_TAIL_BYTES = 2048
_VALID_PROFILES = {"full", "head_tail", "ref_only", "summary_only"}


def _slice_head_tail(
    text: str,
    head_bytes: int,
    tail_bytes: int,
) -> tuple[str, Optional[str]]:
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
    summary: Optional[dict[str, Any]] = None,
    profile: str = "head_tail",
    head_bytes: int = _DEFAULT_HEAD_BYTES,
    tail_bytes: int = _DEFAULT_TAIL_BYTES,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build the canonical MCP tool response.

    ``summary`` is merged into the top-level response (parsed key fields
    such as ``credentials_found``, ``vulnerable``, ``hashes`` …).
    ``extra`` is merged last and can override anything for niche tools.
    """
    if profile not in _VALID_PROFILES:
        profile = "head_tail"

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
        response["output"] = result.stdout
        if result.stderr:
            response["stderr"] = result.stderr
    else:  # head_tail
        head, tail = _slice_head_tail(result.stdout, head_bytes, tail_bytes)
        response["stdout_head"] = head
        if tail is not None:
            response["stdout_tail"] = tail
        # stderr is usually short; include head only.
        if result.stderr:
            err_head, _ = _slice_head_tail(result.stderr, head_bytes, 0)
            response["stderr_head"] = err_head

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
        store = store_getter()
        try:
            data = await store.read(
                call_id, kind=kind,
                head=head or None,
                tail=tail or None,
                offset=offset or None,
                length=length or None,
            )
        except KeyError:
            return {"error": "call_id not found", "call_id": call_id}
        ref = await store.get(call_id)
        return {
            "call_id": call_id,
            "kind": kind,
            "bytes_returned": len(data),
            "total_bytes": (
                ref.stdout_bytes if (ref and kind == "stdout")
                else ref.stderr_bytes if ref else 0
            ),
            "content": data.decode("utf-8", errors="replace"),
        }

    return read_tool_output
