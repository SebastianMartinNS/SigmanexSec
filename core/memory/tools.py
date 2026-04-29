"""Builtin LLM tools exposed by the memory subsystem.

These are *not* MCP tools — they are dispatched in-process by the
orchestrator before any MCP routing. Schemas mirror the OpenAI /
Anthropic tool format used by the rest of the registry.
"""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.memory.manager import MemoryManager


_SCHEMAS: list[dict] = [
    {
        "name": "memory_edit",
        "description": (
            "Replace the contents of one of your core memory blocks. "
            "Use this to keep persona, engagement, targets, findings_summary, "
            "or scratchpad up to date. The block is then visible on every "
            "future turn without spending tool calls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {
                    "type": "string",
                    "description": "Block name (e.g. 'scratchpad', 'findings_summary').",
                },
                "value": {
                    "type": "string",
                    "description": "New full content for the block.",
                },
            },
            "required": ["label", "value"],
        },
    },
    {
        "name": "memory_append",
        "description": (
            "Append text to the end of an existing core memory block. "
            "Useful for incrementally noting new findings or hosts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "label": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["label", "text"],
        },
    },
    {
        "name": "archival_insert",
        "description": (
            "Save a passage of text to long-term archival memory so it can "
            "be retrieved in future turns or future runs via archival_search."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "source": {
                    "type": "string",
                    "description": "Optional tag describing the source (tool name, URL, ...).",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "archival_search",
        "description": (
            "Semantic search over your long-term archival memory. Returns "
            "the top-k most relevant passages (and their similarity score)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "k": {"type": "integer", "minimum": 1, "maximum": 20, "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "recall_search",
        "description": (
            "Full-text search over your full conversation history (including "
            "messages that have been summarized out of the active context)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "k": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                "role": {
                    "type": "string",
                    "enum": ["user", "assistant", "tool", "system"],
                },
            },
            "required": ["query"],
        },
    },
]


BUILTIN_TOOL_NAMES = {t["name"] for t in _SCHEMAS}


def builtin_tool_specs() -> list[dict]:
    """Return the registry-format spec list for the orchestrator."""
    return [dict(t) for t in _SCHEMAS]


async def dispatch_builtin_tool(
    name: str, args: dict, memory: "MemoryManager"
) -> str:
    """Execute a builtin memory tool. Returns a JSON-encoded string."""
    try:
        if name == "memory_edit":
            res = await memory.edit_block(str(args["label"]), str(args["value"]))
            return json.dumps({"ok": True, "message": res})
        if name == "memory_append":
            res = await memory.append_block(str(args["label"]), str(args["text"]))
            return json.dumps({"ok": True, "message": res})
        if name == "archival_insert":
            new_id = await memory.archival_insert(
                str(args["text"]), source=args.get("source")
            )
            return json.dumps({"ok": True, "id": new_id})
        if name == "archival_search":
            results = await memory.archival_search(
                str(args["query"]), k=int(args.get("k", 5))
            )
            return json.dumps({"ok": True, "results": results})
        if name == "recall_search":
            results = await memory.recall_search(
                str(args["query"]),
                k=int(args.get("k", 10)),
                role=args.get("role"),
            )
            return json.dumps({"ok": True, "results": results})
    except Exception as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return json.dumps({"ok": False, "error": f"unknown builtin tool {name!r}"})
