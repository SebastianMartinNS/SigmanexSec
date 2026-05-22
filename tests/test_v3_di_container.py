"""
tests/test_v3_di_container.py — Milestone B3+B6 acceptance.

Covers the custom DI container surface (singleton vs transient, scope
inheritance, fail-fast on unknown types) plus the BaseMCPServer reuse
of the container so multiple MCP servers in the same process share a
single ``AuditLog`` / ``SessionStore`` / ``ToolExecutor`` instance.
"""
from __future__ import annotations

import pytest

from core.di import DIError, ScopedContainer, ServiceContainer, current_container, set_current_container


class _A:
    def __init__(self, label: str = "default") -> None:
        self.label = label


class _B:
    def __init__(self, a: _A) -> None:
        self.a = a


def test_singleton_registration_returns_same_instance():
    c = ServiceContainer()
    c.register(_A, lambda: _A("singleton"))
    a1, a2 = c.resolve(_A), c.resolve(_A)
    assert a1 is a2
    assert a1.label == "singleton"


def test_transient_registration_returns_distinct_instances():
    c = ServiceContainer()
    c.register(_A, lambda: _A("transient"), singleton=False)
    a1, a2 = c.resolve(_A), c.resolve(_A)
    assert a1 is not a2
    assert a1.label == a2.label == "transient"


def test_factory_receives_container_when_arity_one():
    c = ServiceContainer()
    c.register(_A, lambda: _A("A"))
    c.register(_B, lambda cont: _B(cont.resolve(_A)))
    b = c.resolve(_B)
    assert isinstance(b.a, _A)
    assert b.a.label == "A"


def test_resolve_raises_for_unregistered_type():
    c = ServiceContainer()
    class _Z: ...
    with pytest.raises(DIError) as exc:
        c.resolve(_Z)
    assert "no factory registered" in str(exc.value)


def test_try_resolve_returns_none_for_unregistered_type():
    c = ServiceContainer()
    class _Z: ...
    assert c.try_resolve(_Z) is None


def test_register_instance_returns_same_object():
    c = ServiceContainer()
    instance = _A("explicit")
    c.register_instance(_A, instance)
    assert c.resolve(_A) is instance


def test_scoped_overrides_propagate_through_dependent_factory():
    """When a scope overrides ``_A``, a ``_B`` factory registered on the
    parent must see the scoped ``_A`` because the container hands the
    scope (not the parent) to the factory.
    """
    c = ServiceContainer()
    c.register(_A, lambda: _A("parent"))
    c.register(_B, lambda cont: _B(cont.resolve(_A)), singleton=False)
    with c.scope() as scope:
        scope.register(_A, lambda: _A("scoped"))
        b = scope.resolve(_B)
        assert isinstance(b.a, _A)
        assert b.a.label == "scoped"
    # After the scope closes, the parent is unchanged.
    assert c.resolve(_A).label == "parent"


def test_scoped_is_registered_walks_parent():
    c = ServiceContainer()
    c.register(_A, lambda: _A("parent"))
    with c.scope() as scope:
        assert scope.is_registered(_A)
        assert isinstance(scope, ScopedContainer)


def test_current_container_default_is_empty():
    cur = current_container()
    assert isinstance(cur, ServiceContainer)


def test_set_current_container_replaces_default():
    new = ServiceContainer()
    new.register(_A, lambda: _A("marked"))
    set_current_container(new)
    try:
        assert current_container().resolve(_A).label == "marked"
    finally:
        set_current_container(ServiceContainer())


def test_basemcpserver_shares_singletons_across_servers(tmp_path, monkeypatch):
    """Two BaseMCPServer instances in the same process must share the
    same AuditLog / SessionStore / ToolExecutor (the original bug v3.0
    fixes)."""
    monkeypatch.setenv("SAP_DEV_MODE", "1")
    monkeypatch.setenv("SAP_SESSIONS_DIR", str(tmp_path))
    monkeypatch.setenv("SAP_LOGS_DIR", str(tmp_path))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SAP_KEYSALT_PATH", str(tmp_path / ".keysalt"))

    # Use a fresh container so this test does not depend on global state.
    fresh = ServiceContainer()
    set_current_container(fresh)
    try:
        from mcp_servers.base import BaseMCPServer

        srv1 = BaseMCPServer.from_env(name="recon", container=fresh)
        srv2 = BaseMCPServer.from_env(name="exploit", container=fresh)

        assert srv1.audit is srv2.audit
        assert srv1.store is srv2.store
        assert srv1.executor is srv2.executor
        # FastMCP names stay distinct so MCP clients still route correctly.
        assert srv1.mcp.name != srv2.mcp.name
    finally:
        set_current_container(ServiceContainer())
