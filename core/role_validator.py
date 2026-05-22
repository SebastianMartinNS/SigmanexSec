"""
core/role_validator.py — Role-aware capability chokepoint (Milestone C2).

Composes on top of (not in place of) :mod:`core.scope_validator`. The
sequence enforced by :meth:`ToolExecutor.run_request` is:

    1. ``role_validator.assert_tool_allowed(role_id, tool)``
    2. ``role_validator.assert_phase_allowed(role_id, phase)``
    3. ``scope_validator.assert_in_scope(target, engagement_id)`` (legacy)

so a role can be denied a tool the *engagement* is otherwise allowed to
run, without the scope chokepoint being bypassed or duplicated. This is
the [[feedback_security_chokepoints]] pattern: compose, never replace.

Behaviour when no role is bound to the request (``role_id is None``):
the validator is a no-op and the scope chokepoint runs unchanged. This
preserves backward compatibility for the legacy single-agent loop.
"""
from __future__ import annotations

import fnmatch
import logging
from typing import TYPE_CHECKING

from core.models import Phase

if TYPE_CHECKING:
    from agent.roles import Role, RoleRegistry

_log = logging.getLogger(__name__)


class RoleViolation(Exception):
    """Raised when a role is asked to do something outside its capabilities.

    Caught by :meth:`ToolExecutor.run_request` and translated into an
    audit ``scope_violation`` event with ``details["violation_type"] =
    "role"`` so the BLAKE2b chain captures every blocked dispatch.
    """


class RoleValidator:
    """Enforce per-role tool / phase / handoff policy.

    One instance per process, resolved via :func:`get_role_validator`.
    Composes a :class:`RoleRegistry` and *only* reads from it — never
    mutates the catalog at runtime.
    """

    def __init__(self, registry: RoleRegistry) -> None:
        self._registry = registry

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assert_tool_allowed(self, role_id: str, tool: str) -> None:
        """Raise :class:`RoleViolation` if *role_id* may not invoke *tool*.

        Allowlist / denylist work like glob filenames: ``recon_*`` matches
        every tool whose name starts with ``recon_``. ``denied_tools``
        wins over ``allowed_tools`` so a role can be "everything in
        recon_* except recon_active_scan".
        """
        role = self._role(role_id)
        # Denylist takes precedence.
        for pattern in role.denied_tools:
            if fnmatch.fnmatchcase(tool, pattern):
                raise RoleViolation(
                    f"role {role_id!r} explicitly denied from invoking "
                    f"{tool!r} (denied_tools pattern: {pattern!r})"
                )
        if not role.allowed_tools:
            raise RoleViolation(
                f"role {role_id!r} has no allowed_tools — cannot invoke {tool!r}"
            )
        for pattern in role.allowed_tools:
            if fnmatch.fnmatchcase(tool, pattern):
                return
        raise RoleViolation(
            f"role {role_id!r} not allowed to invoke {tool!r} "
            f"(allowed_tools: {sorted(role.allowed_tools)})"
        )

    def assert_phase_allowed(self, role_id: str, phase: Phase | str) -> None:
        """Raise :class:`RoleViolation` if *role_id* may not act in *phase*.

        Roles with ``allowed_phases == []`` may act in any PTES phase.
        """
        role = self._role(role_id)
        if not role.allowed_phases:
            return
        if isinstance(phase, str):
            try:
                phase = Phase(phase)
            except ValueError:
                raise RoleViolation(
                    f"unknown phase {phase!r} requested by role {role_id!r}"
                ) from None
        if phase not in role.allowed_phases:
            allowed = [str(p) for p in role.allowed_phases]
            raise RoleViolation(
                f"role {role_id!r} not allowed in phase {phase!r} "
                f"(allowed_phases: {allowed})"
            )

    def assert_handoff_allowed(self, src_role: str, dst_role: str) -> None:
        """Raise :class:`RoleViolation` if *src_role* may not hand off to *dst_role*."""
        src = self._role(src_role)
        # Sanity: target role must also be registered.
        if self._registry.get(dst_role) is None:
            raise RoleViolation(
                f"handoff target {dst_role!r} is not a registered role"
            )
        if not any(edge.to == dst_role for edge in src.can_handoff_to):
            allowed = [edge.to for edge in src.can_handoff_to] or "[]"
            raise RoleViolation(
                f"role {src_role!r} may not handoff to {dst_role!r} "
                f"(can_handoff_to: {allowed})"
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def role(self, role_id: str) -> Role | None:
        """Public read-only access to the underlying catalog."""
        return self._registry.get(role_id)

    def _role(self, role_id: str) -> Role:
        role = self._registry.get(role_id)
        if role is None:
            raise RoleViolation(f"unknown role {role_id!r}")
        return role


# ----------------------------------------------------------------------
# Process-wide singleton
# ----------------------------------------------------------------------

_VALIDATOR_CACHE: RoleValidator | None = None


def get_role_validator() -> RoleValidator | None:
    """Return the process-wide validator if the role registry is loaded.

    Returns ``None`` when the registry cannot be loaded (e.g. during a
    test that exercises a partial install). Callers in the executor
    chokepoint treat ``None`` as "no role enforcement" — same surface as
    the legacy single-agent loop.
    """
    global _VALIDATOR_CACHE
    if _VALIDATOR_CACHE is not None:
        return _VALIDATOR_CACHE
    try:
        from agent.roles import get_registry
        _VALIDATOR_CACHE = RoleValidator(get_registry())
    except Exception as exc:                              # pragma: no cover
        _log.warning("RoleValidator unavailable: %s", exc)
        return None
    return _VALIDATOR_CACHE


def reset_role_validator_for_tests() -> None:
    """Drop the cached validator so the next ``get_role_validator`` reloads."""
    global _VALIDATOR_CACHE
    _VALIDATOR_CACHE = None
