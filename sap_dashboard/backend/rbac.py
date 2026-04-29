"""
sap_dashboard/backend/rbac.py — Role-based access control (P2.3).

Three roles, ordered by privilege:

    viewer   — read-only access (GET endpoints, audit, KPI, exports).
    operator — viewer + can launch runs, send to interactive sessions,
               write findings, request sudo unlock.
    admin    — operator + system_reset, settings PATCH, GDPR purge,
               user management endpoints (when added).

User directory:
* The legacy single-user model (`SAP_DASHBOARD_USER` + `SAP_DASHBOARD_PASS`) is
  retained for backwards compatibility — that user is treated as `admin`.
* For multi-user deployments, set `SAP_DASHBOARD_USERS` to a JSON map:

      SAP_DASHBOARD_USERS='{
          "alice":   {"pass": "…", "role": "admin"},
          "bob":     {"pass": "…", "role": "operator"},
          "carol":   {"pass": "…", "role": "viewer"}
      }'

  Passwords MUST satisfy the same minimum strength check as the single-user
  bootstrap (≥ 12 chars, not in the well-known weak list).
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
from typing import Optional

from fastapi import Depends, HTTPException, status

from .deps import _expected_creds, require_auth


ROLE_VIEWER   = "viewer"
ROLE_OPERATOR = "operator"
ROLE_ADMIN    = "admin"

_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}


def _load_user_directory() -> dict[str, dict[str, str]]:
    """Return ``{username: {"pass": str, "role": str}}``.

    Always grafts the legacy single-user creds in as ``admin`` when
    ``SAP_DASHBOARD_USER``/``SAP_DASHBOARD_PASS`` are set.
    """
    raw = os.environ.get("SAP_DASHBOARD_USERS")
    directory: dict[str, dict[str, str]] = {}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                for u, info in obj.items():
                    if not isinstance(info, dict):
                        continue
                    pwd = str(info.get("pass", ""))
                    role = str(info.get("role", ROLE_VIEWER)).lower()
                    if role not in _ROLE_RANK:
                        role = ROLE_VIEWER
                    if u and pwd:
                        directory[str(u)] = {"pass": pwd, "role": role}
        except json.JSONDecodeError:
            pass

    legacy = _expected_creds()
    if legacy is not None:
        u, p = legacy
        # Legacy bootstrap user takes precedence and is admin.
        directory[u] = {"pass": p, "role": ROLE_ADMIN}
    return directory


def lookup_role(username: str) -> Optional[str]:
    """Return role name for ``username`` or None if unknown."""
    d = _load_user_directory()
    info = d.get(username)
    if not info:
        return None
    return info["role"]


def verify_user_password(username: str, password: str) -> Optional[str]:
    """Return the role for valid credentials, or None on mismatch."""
    d = _load_user_directory()
    info = d.get(username)
    if not info:
        return None
    if not _secrets.compare_digest(info["pass"].encode(), password.encode()):
        return None
    return info["role"]


def require_role(min_role: str):
    """FastAPI dependency factory that enforces a minimum role.

    Usage::

        @router.delete("/something",
                       dependencies=[Depends(require_role(ROLE_ADMIN))])
        async def kill_it(): ...
    """
    if min_role not in _ROLE_RANK:
        raise ValueError(f"unknown role: {min_role}")
    needed = _ROLE_RANK[min_role]

    def _checker(user: str = Depends(require_auth)) -> str:
        role = lookup_role(user) or ROLE_VIEWER
        if _ROLE_RANK[role] < needed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role '{role}' insufficient; '{min_role}' required",
            )
        return user

    return _checker
