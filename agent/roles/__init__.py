"""
agent/roles/ — Multi-agent role system (Milestone C1).

Roles are YAML-editable so the community can contribute new specialisms
(WebAppPentester, IoTHardwareAuditor, ...) without patching Python. The
loader validates each YAML at startup against :class:`Role` (Pydantic)
plus referential integrity checks (no unknown phases, no dangling
handoff targets, no glob pattern that matches zero tools).

Public API:

    from agent.roles import Role, RoleCapabilityGuard, RoleRegistry, get_registry
"""
from __future__ import annotations

from agent.roles.registry import RoleRegistry, get_registry
from agent.roles.schema import Role, RoleCapabilityGuard, RoleHandoff

__all__ = ["Role", "RoleCapabilityGuard", "RoleHandoff", "RoleRegistry", "get_registry"]
