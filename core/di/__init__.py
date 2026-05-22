"""
core/di/ — Tiny dependency-injection container for SAP-Pentest v3.0.

Replaces the historical ``store = SessionStore()`` / ``audit = AuditLog()``
inline singletons in ``mcp_servers/*_server.py`` with a single registry
the orchestrator and every MCP server resolve at startup. Keeps a custom
implementation rather than pulling ``dependency-injector`` so the supply
chain stays minimal and the surface stays inspectable (≈200 LOC).

Public API:

    from core.di import ServiceContainer, current_container, set_current_container
"""
from __future__ import annotations

from core.di.container import (
    DIError,
    ScopedContainer,
    ServiceContainer,
    current_container,
    set_current_container,
)

__all__ = [
    "DIError",
    "ServiceContainer",
    "ScopedContainer",
    "current_container",
    "set_current_container",
]
