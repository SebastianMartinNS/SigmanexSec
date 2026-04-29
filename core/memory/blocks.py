"""Core memory blocks: persistent, named scratchpads visible every turn.

Inspired by MemGPT/Letta. Each engagement has a small set of blocks
that are concatenated into the system prompt so the LLM always sees
them, no matter how long the conversation grows.
"""
from __future__ import annotations

from dataclasses import dataclass

DEFAULT_BLOCKS: dict[str, tuple[str, int]] = {
    # label -> (initial_value, max_chars)
    "persona": (
        "You are SAP-Agent, a senior offensive-security operator. "
        "You think before you act, prefer least-impact reconnaissance, and "
        "always log evidence into the engagement store.",
        1500,
    ),
    "engagement": ("", 2000),  # filled by orchestrator from engagement record
    "targets": ("", 4000),  # discovered hosts/services digest
    "findings_summary": ("", 4000),  # condensed list of confirmed findings
    "scratchpad": ("", 3000),  # volatile working notes, agent-managed
    # Anti-monotony tactical log (Phase 4). Auto-managed by the orchestrator:
    # records a one-line entry per executed tool with target + outcome so the
    # agent can review what already worked / failed and avoid repetition.
    "tactics_log": (
        "# Tactics log\n"
        "Each line: `[ok|fail|pivot] tool target -> short_outcome`. "
        "Read before re-running a tool to avoid repetition.",
        2500,
    ),
}


@dataclass
class MemoryBlock:
    label: str
    value: str
    max_chars: int

    def render(self) -> str:
        return f"[{self.label} | {len(self.value)}/{self.max_chars}]\n{self.value}".rstrip()


def render_blocks(blocks: list[MemoryBlock]) -> str:
    if not blocks:
        return ""
    body = "\n\n".join(b.render() for b in blocks if b.value or b.label == "persona")
    return (
        "<core_memory>\n"
        "These named blocks are always visible to you. Use the memory_edit / "
        "memory_append tools to keep them up to date.\n"
        f"{body}\n"
        "</core_memory>"
    )
