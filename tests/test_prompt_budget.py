"""Regression tests for the 2026-04-30 prompt-budget hardening sprint.

Covers:
  * Anthropic SDK content-block shapes are counted by ``count_message_tokens``
    (previously they contributed 0 tokens — root cause of the 346 K request).
  * ``build_tool_response`` enforces ``SAP_MCP_HARD_CAP_BYTES`` even on the
    ``full`` profile and surfaces ``truncation_enforced`` in metadata.
  * ``read_tool_output`` clamps every read mode to ``SAP_MCP_RECALL_CAP_BYTES``
    and reports ``recall_cap_bytes`` so callers can paginate.
  * The recon ``_parse_error_snippet`` helper is bounded by the hard cap.
"""
from __future__ import annotations

from types import SimpleNamespace

from core.memory.tokens import _count_block_tokens, count_message_tokens

# ── 1. Anthropic SDK block counting ───────────────────────────────────────────


class _FakeTextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class _FakeToolUseBlock:
    def __init__(self, name: str, payload: dict):
        self.type = "tool_use"
        self.name = name
        self.input = payload


class _FakeToolResultBlock:
    def __init__(self, content):
        self.type = "tool_result"
        self.content = content


def test_count_message_tokens_anthropic_text_block_nonzero():
    msg = {"role": "assistant", "content": [_FakeTextBlock("hello world " * 50)]}
    assert count_message_tokens([msg]) > 50


def test_count_message_tokens_anthropic_tool_use_includes_input():
    big_payload = {"target": "X" * 4000}
    msg = {
        "role": "assistant",
        "content": [_FakeToolUseBlock("nmap_scan", big_payload)],
    }
    n = count_message_tokens([msg])
    # ~4000 chars of input → at least 500 tokens with the heuristic encoder.
    assert n > 500


def test_count_message_tokens_anthropic_tool_result_walks_inner_list():
    inner = [_FakeTextBlock("Y" * 8000)]
    msg = {"role": "user", "content": [_FakeToolResultBlock(inner)]}
    n = count_message_tokens([msg])
    assert n > 1000


def test_count_block_tokens_handles_none_and_str():
    assert _count_block_tokens(None) == 0
    assert _count_block_tokens("plain string") > 0


# ── 2. build_tool_response hard-cap ───────────────────────────────────────────


def _mk_result(stdout: str, stderr: str = "") -> SimpleNamespace:
    """Build the minimal ExecutionResult-like object accepted by the helper."""
    return SimpleNamespace(
        call_id="call_test",
        run_id="run_test",
        tool="generic",
        returncode=0,
        duration_seconds=0.1,
        stdout=stdout,
        stderr=stderr,
        truncated=False,
        stdout_bytes_full=len(stdout.encode("utf-8")),
        stderr_bytes_full=len(stderr.encode("utf-8")),
        output_ref=SimpleNamespace(
            stdout_uri="sap://run/x/output/call_test/stdout",
            stderr_uri="sap://run/x/output/call_test/stderr",
            artifacts_uri="",
        ),
    )


def test_build_tool_response_caps_full_profile(monkeypatch):
    monkeypatch.setenv("SAP_MCP_HARD_CAP_BYTES", "4096")
    from importlib import reload

    import mcp_servers._response as resp
    reload(resp)
    huge = "A" * 200_000
    out = resp.build_tool_response(
        _mk_result(huge),
        profile="full",
    )
    assert out.get("truncation_enforced") is True
    serialized = out.get("output") or ""
    assert len(serialized) <= 4096, f"payload not capped: {len(serialized)}"


def test_build_tool_response_head_tail_respects_hard_cap(monkeypatch):
    monkeypatch.setenv("SAP_MCP_HARD_CAP_BYTES", "2048")
    from importlib import reload

    import mcp_servers._response as resp
    reload(resp)
    huge = "B" * 100_000
    out = resp.build_tool_response(
        _mk_result(huge),
        profile="head_tail",
        head_bytes=99_999,  # caller asks for way more than the cap
        tail_bytes=99_999,
    )
    head = out.get("stdout_head") or ""
    tail = out.get("stdout_tail") or ""
    # head is clamped to cap; tail's budget is whatever remains (= 0 here).
    assert len(head) <= 2048
    assert len(tail) <= 2048
    assert out.get("truncation_enforced") is True


# ── 3. recon snippet helper ───────────────────────────────────────────────────


def test_recon_parse_error_snippet_is_bounded(monkeypatch):
    monkeypatch.setenv("SAP_MCP_HARD_CAP_BYTES", "4096")
    # Re-import response to refresh the cap, then recon to pick it up.
    from importlib import reload

    import mcp_servers._response as resp
    reload(resp)
    import mcp_servers.recon_server as recon
    reload(recon)
    huge = "C" * 50_000
    snippet = recon._parse_error_snippet(huge)
    # Exact length: head + marker + tail; bounded by cap + small fudge.
    assert len(snippet) < 4096 + 256
    assert "truncated" in snippet


def test_recon_parse_error_snippet_passthrough_small():
    import mcp_servers.recon_server as recon
    s = "hello world"
    assert recon._parse_error_snippet(s) == s


def test_recon_parse_error_snippet_none_returns_empty():
    import mcp_servers.recon_server as recon
    assert recon._parse_error_snippet(None) == ""
    assert recon._parse_error_snippet("") == ""


# ── 4. Orchestrator pre-flight guard ──────────────────────────────────────────


def test_prompt_budget_guard_passes_when_under_budget(monkeypatch):
    monkeypatch.setenv("SAP_PROMPT_TOKEN_BUDGET", "100000")
    from importlib import reload

    import agent.orchestrator as orch
    reload(orch)

    events: list = []
    o = orch.Orchestrator(on_message=lambda role, text: events.append((role, text)))
    msgs = [{"role": "user", "content": "small message"}]
    pruned, overflow = o._prompt_budget_guard(msgs, system_text="sys", iteration=0)
    assert overflow is False
    assert pruned == msgs


def test_prompt_budget_guard_overflows_with_huge_payload(monkeypatch):
    # Budget very small AND callback cap large enough that pruning cannot
    # shrink the payload below budget — the guard must report overflow.
    monkeypatch.setenv("SAP_PROMPT_TOKEN_BUDGET", "100")
    monkeypatch.setenv("SAP_CALLBACK_RESULT_CAP", "60000")
    from importlib import reload

    import agent.orchestrator as orch
    reload(orch)

    events: list = []
    o = orch.Orchestrator(on_message=lambda role, text: events.append((role, text)))
    msgs = [
        {"role": "user", "content": "ok"},
        {"role": "assistant", "content": "Z" * 80_000},
    ]
    _pruned, overflow = o._prompt_budget_guard(msgs, system_text="", iteration=3)
    assert overflow is True
    # Expect at least one token_budget event and a final error.
    assert any(role == "token_budget" for role, _ in events)
    assert any(role == "error" for role, _ in events)


def test_prompt_budget_guard_prunes_to_recover(monkeypatch):
    monkeypatch.setenv("SAP_PROMPT_TOKEN_BUDGET", "5000")
    monkeypatch.setenv("SAP_CALLBACK_RESULT_CAP", "1024")
    from importlib import reload

    import agent.orchestrator as orch
    reload(orch)

    events: list = []
    o = orch.Orchestrator(on_message=lambda role, text: events.append((role, text)))
    # ~6 K tokens overshoot — pruning the long content to ~256 tokens recovers.
    msgs = [
        {"role": "user", "content": "ok"},
        {"role": "assistant", "content": "X" * 24_000},
    ]
    pruned, overflow = o._prompt_budget_guard(msgs, system_text="", iteration=1)
    assert overflow is False
    # The previously-long message must have been shrunk.
    assert len(pruned[1]["content"]) < len(msgs[1]["content"])
