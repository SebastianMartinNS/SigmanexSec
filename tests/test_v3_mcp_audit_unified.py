"""
tests/test_v3_mcp_audit_unified.py — W1.4 acceptance.

Before v3.1, every MCP server constructed its own ``SessionStore``,
``AuditLog`` and ``ToolExecutor`` at import time. The result was six
independent BLAKE2b hash chains — one per server — and a forensic
integrity gap (events from a multi-server run could not be cross-walked
as a single chain).

This test pins the v3.1 behaviour: when the six MCP server modules are
imported into the same process with a shared DI container, the
collaborator instances are identical (``is``-comparable), and the
FastMCP server names remain distinct so the MCP routing layer can still
demultiplex tool calls.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.di import ServiceContainer, set_current_container


@pytest.fixture
def _fresh_container_env(tmp_path, monkeypatch):
    """Bootstrap a fresh DI container and per-test temp paths.

    The six MCP server modules instantiate their singletons at *import
    time* (a legacy of the v2.x design that v3.1 keeps for backward
    compat). To make the test deterministic we must:

    1. Point every persistence path at the temp dir, so a previous
       test's cached module does not reuse a stale on-disk state.
    2. Install a brand new empty ServiceContainer as the current one,
       so ``BaseMCPServer.from_env`` builds (and registers as
       singletons) the collaborators inside *this* container.
    3. Drop any previously-imported server module from ``sys.modules``
       so the import-time singletons are rebuilt against the fresh
       container.
    """
    monkeypatch.setenv("SAP_DEV_MODE", "1")
    monkeypatch.setenv("SAP_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("SAP_LOGS_DIR", str(tmp_path))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SAP_KEYSALT_PATH", str(tmp_path / ".keysalt"))

    set_current_container(ServiceContainer())

    import sys
    for mod_name in (
        "mcp_servers.engagement_server",
        "mcp_servers.recon_server",
        "mcp_servers.exploit_server",
        "mcp_servers.blueteam_server",
        "mcp_servers.parrot_server",
        "mcp_servers.osint_server",
    ):
        sys.modules.pop(mod_name, None)
    yield
    set_current_container(ServiceContainer())


def test_six_mcp_servers_share_session_store(_fresh_container_env):
    """All six servers must reference the *same* SessionStore instance."""
    import mcp_servers.engagement_server as eng
    import mcp_servers.recon_server as recon
    import mcp_servers.exploit_server as exp_
    import mcp_servers.blueteam_server as bt
    import mcp_servers.parrot_server as par
    import mcp_servers.osint_server as osi

    stores = [eng.store, recon.store, exp_.store, bt.store, par.store, osi.store]
    assert all(s is stores[0] for s in stores), (
        "SessionStore must be shared across all six MCP servers via the DI "
        f"container; got ids: {[id(s) for s in stores]}"
    )


def test_audit_log_shared_across_tool_bearing_servers(_fresh_container_env):
    """The five servers that own an AuditLog (engagement + 4 tool servers,
    minus blueteam which is read-only) must reference the same instance.

    A single AuditLog instance means a single BLAKE2b hash chain — the
    forensic integrity property v3.1 restores.
    """
    import mcp_servers.engagement_server as eng
    import mcp_servers.recon_server as recon
    import mcp_servers.exploit_server as exp_
    import mcp_servers.parrot_server as par
    import mcp_servers.osint_server as osi

    audits = [eng.audit, recon.audit, exp_.audit, par.audit, osi.audit]
    assert all(a is audits[0] for a in audits), (
        f"AuditLog must be shared; got ids: {[id(a) for a in audits]}"
    )


def test_tool_executor_shared_across_offensive_servers(_fresh_container_env):
    """The four servers that ship a ToolExecutor (recon / exploit / parrot
    / osint) must reference the same instance — same scope chokepoint,
    same audit log, same sudo vault."""
    import mcp_servers.recon_server as recon
    import mcp_servers.exploit_server as exp_
    import mcp_servers.parrot_server as par
    import mcp_servers.osint_server as osi

    execs = [recon._exe, exp_._exe, par._exe, osi._exe]
    assert all(e is execs[0] for e in execs), (
        f"ToolExecutor must be shared; got ids: {[id(e) for e in execs]}"
    )


def test_mcp_server_names_remain_distinct(_fresh_container_env):
    """Sharing collaborators must not collapse the FastMCP routing layer:
    each server still exposes a unique ``pentest-<name>`` to clients."""
    import mcp_servers.engagement_server as eng
    import mcp_servers.recon_server as recon
    import mcp_servers.exploit_server as exp_
    import mcp_servers.blueteam_server as bt
    import mcp_servers.parrot_server as par
    import mcp_servers.osint_server as osi

    names = {eng.mcp.name, recon.mcp.name, exp_.mcp.name,
             bt.mcp.name, par.mcp.name, osi.mcp.name}
    assert names == {
        "pentest-engagement", "pentest-recon", "pentest-exploit",
        "pentest-blueteam", "pentest-parrot", "pentest-osint",
    }


def test_audit_log_path_resolves_from_env(_fresh_container_env, tmp_path):
    """Backward-compat smoke: the legacy ``AUDIT_LOG_PATH`` env still
    controls where the shared audit log writes. Operators upgrading
    from v3.0 must not lose their existing on-disk audit chain."""
    expected = tmp_path / "audit.jsonl"
    import mcp_servers.recon_server as recon
    # AuditLog exposes the underlying path via its internal ``_path``
    # attribute (kept stable since v2.2 hardening).
    assert Path(recon.audit._path) == expected
