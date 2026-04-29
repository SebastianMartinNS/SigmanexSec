"""Tests for mcp_servers._response — canonical MCP tool response shape."""
from __future__ import annotations

import pytest

from core.models import ExecutionResult, Phase, ToolOutputRefModel
from mcp_servers._response import build_tool_response


def _make_result(stdout: str = "x" * 100, stderr: str = "", *, with_ref: bool = True):
    ref = ToolOutputRefModel(
        call_id="call_abc",
        run_id="run_1",
        engagement_id="eng_1",
        tool="nmap",
        stdout_bytes=len(stdout.encode()),
        stderr_bytes=len(stderr.encode()),
        stdout_uri="sap://run/run_1/output/call_abc/stdout",
        stderr_uri="sap://run/run_1/output/call_abc/stderr",
        artifacts_uri="sap://run/run_1/output/call_abc/artifacts",
    ) if with_ref else None
    return ExecutionResult(
        tool="nmap",
        command="nmap -sV 10.0.0.1",
        stdout=stdout,
        stderr=stderr,
        returncode=0,
        duration_seconds=0.5,
        phase=Phase.RECON,
        call_id="call_abc",
        run_id="run_1",
        output_ref=ref,
        stdout_bytes_full=len(stdout.encode()),
        stderr_bytes_full=len(stderr.encode()),
    )


def test_head_tail_default():
    r = _make_result(stdout="A" * 20000)
    out = build_tool_response(r, summary={"vulnerable": True}, profile="head_tail")
    assert out["call_id"] == "call_abc"
    assert out["vulnerable"] is True
    assert "stdout_head" in out and len(out["stdout_head"]) == 8192
    assert "stdout_tail" in out and len(out["stdout_tail"]) == 2048
    assert out["full_size_bytes"]["stdout"] == 20000
    assert out["output_ref"]["stdout_uri"].startswith("sap://run/run_1")


def test_head_tail_short_no_tail():
    r = _make_result(stdout="hello")
    out = build_tool_response(r, profile="head_tail")
    assert out["stdout_head"] == "hello"
    assert "stdout_tail" not in out


def test_full_profile():
    r = _make_result(stdout="ABCDE" * 5000, stderr="warn")
    out = build_tool_response(r, profile="full")
    assert out["output"] == "ABCDE" * 5000
    assert out["stderr"] == "warn"
    assert "stdout_head" not in out


def test_ref_only_profile():
    r = _make_result(stdout="x" * 50)
    out = build_tool_response(r, profile="ref_only")
    assert out["output"] is None
    assert "stdout_head" not in out
    assert out["output_ref"]["stdout_uri"].endswith("/stdout")


def test_summary_only_profile():
    r = _make_result(stdout="noise", stderr="more noise")
    out = build_tool_response(r, profile="summary_only", summary={"creds": ["u:p"]})
    assert out["creds"] == ["u:p"]
    assert "output" not in out and "stdout_head" not in out and "stderr_head" not in out


def test_invalid_profile_falls_back_to_head_tail():
    r = _make_result(stdout="abc")
    out = build_tool_response(r, profile="bogus")
    assert "stdout_head" in out


def test_no_output_ref_when_persistence_off():
    r = _make_result(stdout="abc", with_ref=False)
    out = build_tool_response(r, profile="head_tail")
    assert "output_ref" not in out
    assert out["stdout_head"] == "abc"
