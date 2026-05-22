"""
mcp_servers/base.py — Shared bootstrap for MCP servers (Milestone B6).

Every server in this package historically opened with the same five-line
block::

    _db_path  = os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db")
    _log_path = os.environ.get("AUDIT_LOG_PATH",  "./logs/audit.jsonl")
    store  = SessionStore(_db_path)
    audit  = AuditLog(_log_path)
    _exe   = ToolExecutor(audit_log=audit)

That duplication was the practical reason the team could not enforce a
single :class:`AuditLog` across the orchestrator and the six MCP servers
(each server held a separate handle with a separate hash-chain head).
:class:`BaseMCPServer` centralizes the bootstrap and reuses the
``core.di.ServiceContainer`` whenever one is present.

Usage in a server module::

    from mcp_servers.base import BaseMCPServer

    srv = BaseMCPServer.from_env(name="recon")
    store, audit, executor = srv.store, srv.audit, srv.executor
    mcp = srv.mcp
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from core.audit_log import AuditLog
from core.di import ServiceContainer, current_container
from core.executor import ToolExecutor
from core.session_store import SessionStore
from core.tool_output_store import ToolOutputStore, get_tool_output_store

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_log = logging.getLogger(__name__)


class BaseMCPServer:
    """Single point of bootstrap for an MCP server module.

    Construction prefers the *current DI container* when one is bound for
    the process — that way the orchestrator and every MCP server share
    the same :class:`AuditLog` (so the BLAKE2b chain stays sequential)
    and the same :class:`SessionStore`. When no container is present
    (legacy bootstrap, tests), each server constructs its own instances
    using the same env-var resolution as before so behaviour is
    bit-for-bit compatible with v2.x.
    """

    __slots__ = ("name", "store", "audit", "executor", "output_store", "mcp", "container")

    def __init__(
        self,
        *,
        name: str,
        store: SessionStore,
        audit: AuditLog,
        executor: ToolExecutor,
        output_store: ToolOutputStore | None = None,
        mcp: FastMCP | None = None,
        container: ServiceContainer | None = None,
    ) -> None:
        self.name = name
        self.store = store
        self.audit = audit
        self.executor = executor
        self.output_store = output_store
        self.mcp = mcp
        self.container = container

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_env(
        cls,
        *,
        name: str,
        mcp_title: str | None = None,
        container: ServiceContainer | None = None,
    ) -> BaseMCPServer:
        """Resolve every collaborator from the DI container when present.

        ``mcp_title`` is the FastMCP server name; defaults to
        ``"pentest-<name>"`` to preserve historical naming for clients.
        """
        from mcp.server.fastmcp import FastMCP

        container = container or current_container()
        store = _resolve_or_build(container, SessionStore, _build_session_store)
        audit = _resolve_or_build(container, AuditLog, _build_audit_log)
        executor = _resolve_or_build(
            container,
            ToolExecutor,
            lambda: ToolExecutor(audit_log=audit),
        )
        # OutputStore wires lazily inside ToolExecutor; we only request it
        # eagerly here so `register_resource_handlers` does not have to
        # call ``get_tool_output_store`` each turn.
        output_store = (
            container.try_resolve(ToolOutputStore)
            if container.is_registered(ToolOutputStore)
            else get_tool_output_store()
        )
        title = mcp_title or f"pentest-{name}"
        return cls(
            name=name,
            store=store,
            audit=audit,
            executor=executor,
            output_store=output_store,
            mcp=FastMCP(title),
            container=container,
        )

    # ------------------------------------------------------------------
    # Convenience: register the boilerplate response handlers + run-context
    # tool the legacy servers all install.
    # ------------------------------------------------------------------

    def install_default_handlers(self) -> None:
        """Mount the shared resource handlers + run-context tool.

        Mirrors what each server module does today (see
        ``mcp_servers/recon_server.py:51-52``). Pulled into the base so a
        new contributor does not need to copy three import lines.
        """
        from mcp_servers._response import (
            register_resource_handlers,
            register_run_context_tool,
        )

        if self.mcp is None:
            raise RuntimeError("BaseMCPServer.mcp is unset; nothing to install on")

        register_resource_handlers(
            self.mcp,
            lambda: self.output_store or get_tool_output_store(),
            server_suffix=self.name,
        )
        register_run_context_tool(self.mcp, self.executor, server_suffix=self.name)


# ----------------------------------------------------------------------
# Resolution helpers
# ----------------------------------------------------------------------


def _resolve_or_build(
    container: ServiceContainer,
    cls: type,
    factory,
) -> Any:
    """Resolve *cls* from the container or fall back to *factory*.

    Keeps the legacy code path (env-var → ``SessionStore("…")``) alive
    when the orchestrator has not bootstrapped the container yet.
    """
    if container.is_registered(cls):
        return container.resolve(cls)
    instance = factory()
    # Cache the just-built instance so subsequent ``from_env`` calls
    # (e.g. multiple servers in the same process) share it.
    container.register_instance(cls, instance)
    return instance


def _build_session_store() -> SessionStore:
    db_path = os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db")
    return SessionStore(db_path)


def _build_audit_log() -> AuditLog:
    log_path = os.environ.get("AUDIT_LOG_PATH", "./logs/audit.jsonl")
    return AuditLog(log_path)
