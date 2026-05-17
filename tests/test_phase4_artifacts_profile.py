"""Phase 4: auto-artifacts injection + response profile resolution."""
from __future__ import annotations

from core.parrot_catalog import (
    auto_artifact_flags,
    materialize_artifact_flags,
    response_profile_for,
)


def test_auto_artifact_nmap_injects_oA():
    flags = auto_artifact_flags("nmap", ["-sV", "10.0.0.1"])
    assert flags == ["-oA", "{artifacts}/nmap"]


def test_auto_artifact_nmap_skipped_when_oA_already_present():
    flags = auto_artifact_flags("nmap", ["-sV", "-oA", "/tmp/me", "10.0.0.1"])
    assert flags == []


def test_auto_artifact_nmap_skipped_when_oN_present():
    flags = auto_artifact_flags("nmap", ["-sV", "-oN", "/tmp/me.txt", "10.0.0.1"])
    assert flags == []


def test_auto_artifact_unknown_tool_returns_empty():
    assert auto_artifact_flags("does-not-exist", ["--foo"]) == []


def test_auto_artifact_sqlmap_output_dir():
    flags = auto_artifact_flags("sqlmap", ["-u", "http://t/?id=1"])
    assert flags == ["--output-dir", "{artifacts}/sqlmap"]


def test_auto_artifact_sqlmap_skipped_with_existing_output_dir():
    flags = auto_artifact_flags(
        "sqlmap", ["-u", "http://t/?id=1", "--output-dir", "/tmp/o"]
    )
    assert flags == []


def test_materialize_replaces_placeholder():
    out = materialize_artifact_flags(["-oA", "{artifacts}/nmap"], "/r/sessions/runs/x/tool_outputs/call_x/artifacts")
    assert out == ["-oA", "/r/sessions/runs/x/tool_outputs/call_x/artifacts/nmap"]


def test_response_profile_explicit_descriptor_wins():
    d = {"category": "recon", "response_profile": "ref_only",
         "response_head_bytes": 1024, "response_tail_bytes": 256}
    p = response_profile_for(d)
    assert p == {"profile": "ref_only", "head_bytes": 1024, "tail_bytes": 256}


def test_response_profile_category_default_blueteam():
    p = response_profile_for({"category": "blueteam"})
    assert p["profile"] == "summary_only"


def test_response_profile_fallback_head_tail():
    p = response_profile_for({"category": "unknown_cat"})
    assert p["profile"] == "head_tail"
    assert p["head_bytes"] == 8192
    assert p["tail_bytes"] == 2048
