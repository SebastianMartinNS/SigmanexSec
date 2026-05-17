"""
Tests for the Phase 0/1/2/6 fixes shipped to break the
``parrot_nuclei_scan`` permutation loop.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


# ── Phase 1: schema accepts CSV severity ──────────────────────────────────
def test_nuclei_severity_accepts_csv():
    from core.parrot_catalog import get_descriptor, render_argv

    d = get_descriptor("nuclei_scan")
    assert d is not None, "nuclei_scan descriptor must be present"
    argv, _ = render_argv(d, {
        "target": "http://example.test",
        "severity": "critical,high,medium",
    })
    # CSV severity must reach nuclei as a single argv element.
    assert "critical,high,medium" in argv
    assert argv[argv.index("-severity") + 1] == "critical,high,medium"


def test_nuclei_severity_rejects_garbage():
    from core.parrot_catalog import CatalogError, get_descriptor, render_argv

    d = get_descriptor("nuclei_scan")
    with pytest.raises(CatalogError):
        render_argv(d, {"target": "http://x", "severity": "extreme"})


def test_schema_pattern_validator_generic():
    """``pattern`` keyword is supported on any string property."""
    from core.parrot_catalog import CatalogError, _validate_args

    desc = {
        "name": "fake",
        "args_schema": {
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "pattern": r"^(low|medium|high)$",
                },
            },
        },
    }
    _validate_args(desc, {"level": "medium"})  # ok
    with pytest.raises(CatalogError):
        _validate_args(desc, {"level": "lowest"})


# ── Phase 2: empty-output diagnosis ───────────────────────────────────────
def _fake_result(*, stdout="", stderr="", rc=0):
    from core.models import ExecutionResult
    return ExecutionResult(
        tool="nuclei",
        command="nuclei -target http://x",
        stdout=stdout,
        stderr=stderr,
        returncode=rc,
        duration_seconds=0.1,
    )


def test_diagnose_host_unreachable():
    from mcp_servers._response import diagnose_empty_output

    diag = diagnose_empty_output(_fake_result(
        stderr="dial tcp 1.2.3.4:443: i/o timeout\n"
    ))
    assert diag is not None
    assert diag["kind"] == "host_unreachable"


def test_diagnose_no_templates():
    from mcp_servers._response import diagnose_empty_output

    diag = diagnose_empty_output(_fake_result(
        stderr="FATL no templates were loaded\n"
    ))
    assert diag is not None
    assert diag["kind"] == "no_templates"


def test_diagnose_no_findings_when_silent():
    from mcp_servers._response import diagnose_empty_output

    diag = diagnose_empty_output(_fake_result(stderr=""))
    assert diag is not None
    assert diag["kind"] == "no_findings"


def test_diagnose_skips_when_stdout_present():
    from mcp_servers._response import diagnose_empty_output

    diag = diagnose_empty_output(_fake_result(stdout="result\n"))
    assert diag is None


def test_build_response_includes_diagnosis_for_empty_scan():
    from mcp_servers._response import build_tool_response

    resp = build_tool_response(_fake_result(
        stderr="connection refused\n"
    ), profile="head_tail")
    assert "diagnosis" in resp
    assert resp["diagnosis"]["kind"] == "host_unreachable"


def test_build_response_extra_overrides_diagnosis():
    """Caller-supplied ``diagnosis`` in ``extra`` must win."""
    from mcp_servers._response import build_tool_response

    resp = build_tool_response(
        _fake_result(stderr="connection refused\n"),
        extra={"diagnosis": {"kind": "custom", "evidence": "x"}},
    )
    assert resp["diagnosis"]["kind"] == "custom"


# ── Phase 6: empty_output failure-class + playbook fallback ───────────────
def test_classify_failure_recognises_empty_output_diagnosis():
    from core.adaptive.repetition import RepetitionHandler

    text = '{"returncode": 0, "diagnosis": {"kind": "host_unreachable", "evidence": "x"}}'
    assert RepetitionHandler.classify_failure(text) == "empty_output"


def test_web_playbook_has_empty_output_chain():
    from core.adaptive.playbook import PlaybookRouter

    pb = PlaybookRouter.load("web")
    assert pb is not None
    chain = pb.fallback_for("empty_output")
    assert chain, "web.yaml must define fallback_chain.empty_output"


def test_repetition_pivot_via_empty_output_chain():
    from core.adaptive.playbook import PlaybookRouter
    from core.adaptive.repetition import RepetitionHandler

    pb = PlaybookRouter.load("web")
    h = RepetitionHandler(max_pivots=3)
    suggestion = h.suggest(
        tool_name="nuclei_scan",
        last_result='{"diagnosis":{"kind":"host_unreachable","evidence":"x"}}',
        playbook=pb,
    )
    assert suggestion.failure_class == "empty_output"
    assert suggestion.fallback_kind in ("playbook", "family")
