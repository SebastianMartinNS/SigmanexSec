"""Integration tests: SAP_SANDBOX=warn must NOT change the tool execution
flow (the unwrapped argv is what runs) but MUST emit a sandbox.warn audit
event carrying the would-have-wrapped argv.

These tests stub the subprocess layer rather than driving real binaries so
they run without bwrap installed and without privileges."""

from __future__ import annotations

import pytest

from core import sandbox
from core.executor import ToolExecutor
from core.models import AuditEntry, Phase


class _CapturingAudit:
    """Stand-in for core.audit_log.AuditLog that captures entries in memory."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    async def write(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    sandbox.reset_caches()
    monkeypatch.delenv("SAP_SANDBOX", raising=False)
    # Monkey-patch the allowlist so we can use a fake tool without polluting
    # config.yaml. We also disable output persistence to avoid touching the
    # SessionStore for these unit tests.
    import core.executor as ex
    monkeypatch.setattr(ex, "_allowed_tools", lambda: {"echo", "nmap"})
    monkeypatch.setattr(ex, "_persist_outputs", lambda: False)
    monkeypatch.setenv("SAP_SESSIONS_DIR", str(tmp_path / "sessions"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    yield
    sandbox.reset_caches()


@pytest.mark.asyncio
async def test_warn_mode_runs_unwrapped_command_and_audits(monkeypatch):
    """With SAP_SANDBOX=warn, _exec must receive the *unwrapped* command,
    AND a sandbox.warn audit entry must be appended before execution."""
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    audit = _CapturingAudit()
    executor = ToolExecutor(audit_log=audit, scope_validator=None)

    seen_cmd: dict[str, list[str]] = {}

    async def _fake_exec(cmd, timeout, cwd, sudo_password=None):
        seen_cmd["cmd"] = list(cmd)
        return ("OK\n", "", 0)

    monkeypatch.setattr(executor, "_exec", _fake_exec)

    result = await executor.run(
        "echo", ["hello"],
        engagement_id="eng_warn_1",
        phase=Phase.RECON,
        sandbox_category="recon",
    )

    assert result.returncode == 0
    # Critical assertion: the command that ACTUALLY ran is the unwrapped one.
    assert seen_cmd["cmd"] == ["echo", "hello"]

    # And a sandbox.warn audit entry is present, carrying the bwrap-wrapped
    # argv that *would* have run under enforcement.
    sandbox_entries = [e for e in audit.entries if e.action == "sandbox.warn"]
    assert len(sandbox_entries) == 1
    entry = sandbox_entries[0]
    assert entry.engagement_id == "eng_warn_1"
    assert entry.details["tool"] == "echo"
    assert entry.details["profile"] == "recon"
    notes = entry.details.get("notes") or []
    # In CI without bwrap installed the wrapped argv is empty + a note
    # documents the absence. In a dev host with bwrap installed it carries
    # the real bwrap command.
    would = entry.details.get("would_have_wrapped_argv") or []
    if would:
        assert would[0] == "bwrap"
        assert "echo" in would
        assert "hello" in would
    else:
        assert any("bwrap" in n for n in notes)


@pytest.mark.asyncio
async def test_off_mode_emits_no_sandbox_audit(monkeypatch):
    """SAP_SANDBOX=off must produce zero sandbox.* audit entries."""
    monkeypatch.setenv("SAP_SANDBOX", "off")
    audit = _CapturingAudit()
    executor = ToolExecutor(audit_log=audit, scope_validator=None)

    async def _fake_exec(cmd, timeout, cwd, sudo_password=None):
        return ("hi\n", "", 0)

    monkeypatch.setattr(executor, "_exec", _fake_exec)
    await executor.run(
        "echo", ["hi"],
        engagement_id="eng_off_1",
        sandbox_category="recon",
    )

    assert not any(e.action.startswith("sandbox.") for e in audit.entries)


@pytest.mark.asyncio
async def test_sudo_required_tool_skips_sandbox_in_v23(monkeypatch):
    """v2.3 limitation: sudo-required tools are NOT wrapped (user-ns strips
    setuid → sudo would refuse). Verified here by asserting:
      - the resulting cmd starts with `sudo -S -p ""`
      - no sandbox.warn audit event is emitted for that invocation
    A v2.4 follow-up will introduce a privileged-sandbox proxy."""
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    audit = _CapturingAudit()

    # Stub the sudo vault to behave as already-unlocked, returning a dummy
    # password without invoking the broker.
    class _StubVault:
        async def is_unlocked(self) -> bool:
            return True

        def borrow(self):
            class _Ctx:
                async def __aenter__(self_inner):
                    return bytearray(b"correct horse")

                async def __aexit__(self_inner, *_):
                    return False

            return _Ctx()

        async def record_success(self) -> None:
            pass

        async def record_failure(self) -> bool:
            return False

    executor = ToolExecutor(
        audit_log=audit, scope_validator=None, sudo_vault=_StubVault(),
    )

    seen_cmd: dict[str, list[str]] = {}

    async def _fake_exec(cmd, timeout, cwd, sudo_password=None):
        seen_cmd["cmd"] = list(cmd)
        return ("", "", 0)

    monkeypatch.setattr(executor, "_exec", _fake_exec)

    await executor.run(
        "nmap", ["-sS", "203.0.113.1"],
        engagement_id="eng_sudo_1",
        sandbox_category="recon",
        requires_sudo=True,
        sudo_reason="SYN scan",
    )

    assert seen_cmd["cmd"][0] == "sudo"
    assert "nmap" in seen_cmd["cmd"]
    assert not any(e.action == "sandbox.warn" for e in audit.entries)


@pytest.mark.asyncio
async def test_warn_mode_falls_back_to_parrot_profile_when_category_unknown(monkeypatch):
    """A category hint that doesn't match the DEFAULT_PROFILE_BY_CATEGORY
    table must fall through to the conservative 'parrot' profile."""
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    audit = _CapturingAudit()
    executor = ToolExecutor(audit_log=audit, scope_validator=None)

    async def _fake_exec(cmd, timeout, cwd, sudo_password=None):
        return ("", "", 0)

    monkeypatch.setattr(executor, "_exec", _fake_exec)
    await executor.run(
        "echo", ["fallback-test"],
        engagement_id="eng_fb",
        sandbox_category="something_unknown",
    )

    sandbox_entries = [e for e in audit.entries if e.action == "sandbox.warn"]
    assert len(sandbox_entries) == 1
    assert sandbox_entries[0].details["profile"] == "parrot"


@pytest.mark.asyncio
async def test_explicit_sandbox_profile_overrides_category(monkeypatch):
    monkeypatch.setenv("SAP_SANDBOX", "warn")
    audit = _CapturingAudit()
    executor = ToolExecutor(audit_log=audit, scope_validator=None)

    async def _fake_exec(cmd, timeout, cwd, sudo_password=None):
        return ("", "", 0)

    monkeypatch.setattr(executor, "_exec", _fake_exec)
    await executor.run(
        "echo", ["override"],
        engagement_id="eng_override",
        sandbox_category="recon",
        sandbox_profile="exploit",
    )

    sandbox_entries = [e for e in audit.entries if e.action == "sandbox.warn"]
    assert sandbox_entries[0].details["profile"] == "exploit"
