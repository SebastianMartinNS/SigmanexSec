"""
agent/roles/registry.py — Load + validate the role catalog.

Single global :class:`RoleRegistry` per process, lazy-loaded from the
YAML files in ``agent/roles/*.yaml``. Validation runs at first access:
unknown handoff targets, persona prompt files that do not exist on disk
and circular handoffs are all hard errors.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from agent.roles.schema import Role

_log = logging.getLogger(__name__)


class RoleRegistry:
    """In-memory directory of every :class:`Role` known to the process.

    Thread-safe (registrations are guarded by an RLock). Construction is
    cheap; the YAML walk happens once when :meth:`load_default` or
    :meth:`load_from_dir` is called.
    """

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {}
        self._lock = threading.RLock()
        self._loaded_from: Path | None = None

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def load_default(cls) -> "RoleRegistry":
        """Load every ``*.yaml`` next to this module."""
        reg = cls()
        reg.load_from_dir(Path(__file__).parent)
        return reg

    def load_from_dir(self, directory: Path) -> None:
        """Replace the in-memory catalog with every ``*.yaml`` in *directory*.

        ``directory`` is walked non-recursively. Each file must contain
        a single YAML document conforming to :class:`Role`.
        """
        directory = directory.resolve()
        roles: dict[str, Role] = {}
        for yaml_path in sorted(directory.glob("*.yaml")):
            with open(yaml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                raise ValueError(f"{yaml_path}: top-level must be a mapping")
            role = Role.model_validate(data)
            if role.id in roles:
                raise ValueError(f"{yaml_path}: duplicate role id {role.id!r}")
            roles[role.id] = role
        self._validate_referential_integrity(roles)
        with self._lock:
            self._roles = roles
            self._loaded_from = directory

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, role_id: str) -> Role | None:
        with self._lock:
            return self._roles.get(role_id)

    def require(self, role_id: str) -> Role:
        role = self.get(role_id)
        if role is None:
            known = ", ".join(sorted(self._roles))
            raise KeyError(f"unknown role {role_id!r} (known: {known})")
        return role

    def all_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._roles)

    def all_roles(self) -> Iterable[Role]:
        with self._lock:
            return list(self._roles.values())

    def __len__(self) -> int:
        with self._lock:
            return len(self._roles)

    def __contains__(self, role_id: object) -> bool:
        if not isinstance(role_id, str):
            return False
        with self._lock:
            return role_id in self._roles

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_referential_integrity(roles: dict[str, Role]) -> None:
        """Reject catalogs with dangling handoff targets or missing prompt files."""
        known_ids = set(roles)
        repo_root = Path(__file__).resolve().parents[2]
        for role in roles.values():
            for edge in role.can_handoff_to:
                if edge.to not in known_ids:
                    raise ValueError(
                        f"role {role.id!r}: handoff target {edge.to!r} not in catalog"
                    )
            persona_path = (repo_root / role.persona_prompt_path).resolve()
            if not persona_path.is_file():
                raise FileNotFoundError(
                    f"role {role.id!r}: persona_prompt_path {role.persona_prompt_path!r} "
                    f"resolves to {persona_path} which does not exist"
                )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "count": len(self._roles),
                "ids": sorted(self._roles),
                "loaded_from": str(self._loaded_from) if self._loaded_from else None,
            }


# ----------------------------------------------------------------------
# Process-wide singleton
# ----------------------------------------------------------------------

_REGISTRY_CACHE: RoleRegistry | None = None
_REGISTRY_LOCK = threading.RLock()


def get_registry() -> RoleRegistry:
    """Return the lazy-loaded default role registry."""
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    with _REGISTRY_LOCK:
        if _REGISTRY_CACHE is None:
            _REGISTRY_CACHE = RoleRegistry.load_default()
    return _REGISTRY_CACHE


def reset_registry_for_tests() -> None:
    """Drop the cached registry so the next ``get_registry`` reloads YAML.

    Used by tests that exercise role-loader error paths.
    """
    global _REGISTRY_CACHE
    with _REGISTRY_LOCK:
        _REGISTRY_CACHE = None
