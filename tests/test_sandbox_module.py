"""Unit tests for core/sandbox.py — mode logic, profile loading, bwrap argv
composition. Does NOT require bwrap to be installed; the bwrap-needed
behaviour lives in tests/test_sandbox_bwrap.py (gated by the ``sandbox``
marker so it only runs on the self-hosted runner)."""

from __future__ import annotations

import json
import shutil

import pytest

from core import sandbox


@pytest.fixture(autouse=True)
def _reset_caches(monkeypatch):
    """Force fresh profile resolution + drop module env between tests."""
    sandbox.reset_caches()
    monkeypatch.delenv("SAP_SANDBOX", raising=False)
    monkeypatch.delenv("SAP_SANDBOX_PROFILE_DIR", raising=False)
    yield
    sandbox.reset_caches()


# ── current_mode / env parsing ────────────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    (None, "warn"),
    ("", "warn"),
    ("warn", "warn"),
    ("on", "on"),
    ("1", "on"),
    ("true", "on"),
    ("ENFORCE", "on"),
    ("Yes", "on"),
    ("off", "off"),
    ("0", "off"),
    ("FALSE", "off"),
    ("disable", "off"),
    ("garbage", "warn"),
])
def test_current_mode_env_parsing(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("SAP_SANDBOX", raising=False)
    else:
        monkeypatch.setenv("SAP_SANDBOX", raw)
    assert sandbox.current_mode() == expected


# ── Profile loading ───────────────────────────────────────────────────────


def test_shipped_profiles_are_loadable():
    """All six profiles bundled in deploy/sandbox/profiles/ must parse and
    have the keys expected by _build_bwrap_argv."""
    for name in ("recon", "exploit", "osint", "blueteam", "parrot", "engagement"):
        prof = sandbox.load_profile(name)
        assert prof["name"] == name
        assert "bind_ro" in prof
        assert "network_policy" in prof
        assert prof["network_policy"] in {"in_scope", "domain_allowlist", "none"}
        assert "caps_drop" in prof


def test_load_profile_missing_raises(monkeypatch, tmp_path):
    """Pointing SAP_SANDBOX_PROFILE_DIR at an empty directory must produce
    FileNotFoundError on every name."""
    monkeypatch.setenv("SAP_SANDBOX_PROFILE_DIR", str(tmp_path))
    sandbox.reset_caches()
    with pytest.raises(FileNotFoundError):
        sandbox.load_profile("recon")


def test_resolve_profile_fallback_to_parrot():
    assert sandbox.resolve_profile(None) == "parrot"
    assert sandbox.resolve_profile(None, category_hint="unknown") == "parrot"
    assert sandbox.resolve_profile(None, category_hint="recon") == "recon"
    assert sandbox.resolve_profile("custom") == "custom"


# ── wrap() mode behaviour ─────────────────────────────────────────────────


def test_wrap_off_returns_argv_unchanged(monkeypatch):
    monkeypatch.setenv("SAP_SANDBOX", "off")
    decision = sandbox.wrap("recon", ["nmap", "-sS", "203.0.113.1"])
    assert decision.mode == "off"
    assert decision.wrapped_argv == ["nmap", "-sS", "203.0.113.1"]
    assert decision.would_have_wrapped_argv is None
    assert not decision.enforced


def test_wrap_warn_returns_argv_unchanged_but_carries_would_have(monkeypatch):
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    decision = sandbox.wrap("recon", ["nmap", "-sV", "203.0.113.1"], run_id="run_test_1")
    assert decision.mode == "warn"
    assert decision.wrapped_argv == ["nmap", "-sV", "203.0.113.1"]
    assert not decision.enforced
    if shutil.which("bwrap"):
        # bwrap available: would_have_wrapped_argv must be the real bwrap line.
        assert decision.would_have_wrapped_argv is not None
        assert decision.would_have_wrapped_argv[0] == "bwrap"
        assert "nmap" in decision.would_have_wrapped_argv
    else:
        # bwrap missing: the note documents it; would_have stays None.
        assert any("bwrap" in n for n in decision.notes)


def test_wrap_warn_with_missing_profile_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    monkeypatch.setenv("SAP_SANDBOX_PROFILE_DIR", str(tmp_path))
    sandbox.reset_caches()
    decision = sandbox.wrap("nonexistent_profile", ["echo", "hello"])
    assert decision.mode == "warn"
    assert decision.wrapped_argv == ["echo", "hello"]
    assert any("profile not found" in n for n in decision.notes)


def test_wrap_on_with_missing_profile_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("SAP_SANDBOX", "on")
    monkeypatch.setenv("SAP_SANDBOX_PROFILE_DIR", str(tmp_path))
    sandbox.reset_caches()
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.wrap("nonexistent_profile", ["echo", "hello"])


def test_wrap_on_without_bwrap_raises(monkeypatch):
    """When bwrap is not on PATH, enforce mode must refuse rather than
    silently letting the tool escape."""
    monkeypatch.setenv("SAP_SANDBOX", "on")
    monkeypatch.setattr(sandbox.shutil, "which", lambda _name: None)
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.wrap("recon", ["nmap", "203.0.113.1"])


# ── _build_bwrap_argv: spot checks on profile semantics ──────────────────


def test_build_bwrap_argv_applies_network_unshare_only_for_none_policy():
    """Policies ``in_scope`` and ``domain_allowlist`` keep network attached;
    only ``none`` triggers --unshare-net (full network isolation)."""
    base = {
        "name": "p", "bind_ro": [], "caps_drop": ["ALL"],
    }
    argv_in_scope = sandbox._build_bwrap_argv(
        {**base, "network_policy": "in_scope"}, ["echo", "x"], run_id="r"
    )
    argv_allowlist = sandbox._build_bwrap_argv(
        {**base, "network_policy": "domain_allowlist"}, ["echo", "x"], run_id="r"
    )
    argv_none = sandbox._build_bwrap_argv(
        {**base, "network_policy": "none"}, ["echo", "x"], run_id="r"
    )
    assert "--unshare-net" not in argv_in_scope
    assert "--unshare-net" not in argv_allowlist
    assert "--unshare-net" in argv_none


def test_build_bwrap_argv_drops_all_caps_by_default():
    argv = sandbox._build_bwrap_argv(
        {"name": "p", "bind_ro": [], "network_policy": "none", "caps_drop": ["ALL"]},
        ["true"], run_id="r",
    )
    assert ["--cap-drop", "ALL"] == argv[argv.index("--cap-drop"):argv.index("--cap-drop") + 2]


def test_build_bwrap_argv_appends_tool_after_double_dash():
    argv = sandbox._build_bwrap_argv(
        {"name": "p", "bind_ro": [], "network_policy": "none", "caps_drop": []},
        ["nmap", "-sS", "203.0.113.1"], run_id="r",
    )
    dash_idx = argv.index("--")
    assert argv[dash_idx + 1:] == ["nmap", "-sS", "203.0.113.1"]


def test_build_bwrap_argv_creates_workdir_under_run_id(tmp_path):
    profile = {
        "name": "p",
        "bind_ro": [],
        "network_policy": "none",
        "caps_drop": [],
        "workdir_template": str(tmp_path / "sap-{run_id}" / "work"),
        "workdir_mount": "/work",
    }
    argv = sandbox._build_bwrap_argv(profile, ["true"], run_id="run_xyz")
    expected_host = tmp_path / "sap-run_xyz" / "work"
    assert expected_host.is_dir()
    assert "--bind" in argv
    bind_idx = argv.index("--bind")
    assert argv[bind_idx + 1] == str(expected_host)
    assert argv[bind_idx + 2] == "/work"


def test_load_profile_is_cached(tmp_path, monkeypatch):
    """Second call must not re-read the file from disk."""
    monkeypatch.setenv("SAP_SANDBOX_PROFILE_DIR", str(tmp_path))
    sandbox.reset_caches()
    payload = {"name": "x", "bind_ro": [], "network_policy": "none", "caps_drop": ["ALL"]}
    (tmp_path / "x.json").write_text(json.dumps(payload))
    first = sandbox.load_profile("x")
    # Mutate file on disk; cached call must still see the old contents.
    (tmp_path / "x.json").write_text(json.dumps({**payload, "name": "MUTATED"}))
    second = sandbox.load_profile("x")
    assert first is second
    assert second["name"] == "x"
