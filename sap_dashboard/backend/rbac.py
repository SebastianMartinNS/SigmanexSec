"""
sap_dashboard/backend/rbac.py — Role-based access control + Argon2id verify.

Three roles, ordered by privilege:

    viewer   — read-only access (GET endpoints, audit, KPI, exports).
    operator — viewer + can launch runs, send to interactive sessions,
               write findings, request sudo unlock.
    admin    — operator + system_reset, settings PATCH, GDPR purge,
               user management endpoints.

User directory format (``SAP_DASHBOARD_USERS`` env var, JSON object):

* **v2.3+ — Argon2id hashed (recommended)**::

      {"alice": {"pass_hash": "$argon2id$...", "role": "operator"}}

* **legacy plaintext (deprecated in v2.3, removal target v2.4)**::

      {"alice": {"pass": "plaintext", "role": "operator"}}

  The legacy form still works for one release of grace; each invocation
  that falls back to plaintext compare emits an ``auth.cred.plaintext.deprecated``
  audit event so operators see the warning in the dashboard.

* The legacy single-user model (``SAP_DASHBOARD_USER`` + ``SAP_DASHBOARD_PASS``)
  is also retained — that bootstrap user is treated as ``admin`` and its
  password is verified via the same hash/plaintext-fallback path.
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
from typing import Any

from fastapi import Depends, HTTPException, status

from core.credentials import looks_like_argon2id, verify_password
from core.logging import get_logger

from .deps import _expected_creds, require_auth

_log = get_logger("dashboard.rbac")

ROLE_VIEWER   = "viewer"
ROLE_OPERATOR = "operator"
ROLE_ADMIN    = "admin"

_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_OPERATOR: 1, ROLE_ADMIN: 2}


def _load_user_directory() -> dict[str, dict[str, str]]:
    """Return ``{username: {"pass_hash"|"pass": str, "role": str}}``.

    The fields ``pass_hash`` (Argon2id encoded) and ``pass`` (plaintext,
    legacy) are mutually exclusive; if both are provided, ``pass_hash``
    wins and the plaintext is dropped.

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
                    entry = _entry_from_user_record(info)
                    role = str(info.get("role", ROLE_VIEWER)).lower()
                    if role not in _ROLE_RANK:
                        role = ROLE_VIEWER
                    if u and entry:
                        entry["role"] = role
                        directory[str(u)] = entry
        except json.JSONDecodeError:
            pass

    legacy = _expected_creds()
    if legacy is not None:
        u, p = legacy
        # Legacy bootstrap user takes precedence and is admin.
        if looks_like_argon2id(p):
            directory[u] = {"pass_hash": p, "role": ROLE_ADMIN}
        else:
            directory[u] = {"pass": p, "role": ROLE_ADMIN}
    return directory


def _entry_from_user_record(info: dict[str, Any]) -> dict[str, str] | None:
    """Normalise a single SAP_DASHBOARD_USERS entry: prefer pass_hash, fall
    back to plaintext pass for backwards-compat."""
    pass_hash = str(info.get("pass_hash", "")).strip()
    if pass_hash:
        if looks_like_argon2id(pass_hash):
            return {"pass_hash": pass_hash}
        # Marked as hash but not Argon2id-shaped → reject the entry.
        return None
    plaintext = str(info.get("pass", "")).strip()
    if plaintext:
        return {"pass": plaintext}
    return None


def lookup_role(username: str) -> str | None:
    """Return role name for ``username`` or None if unknown."""
    d = _load_user_directory()
    info = d.get(username)
    if not info:
        return None
    return info["role"]


def verify_user_password(username: str, password: str) -> str | None:
    """Return the role for valid credentials, or None on mismatch.

    Verification order, per user record:

    1. If ``pass_hash`` is set → Argon2id verify (constant-time, side-channel
       resistant). This is the v2.3+ default and the only path we ship as
       documented.

    2. If ``pass`` is set (plaintext, legacy) → fall back to
       ``secrets.compare_digest`` and emit an ``auth.cred.plaintext.deprecated``
       audit event so the operator notices and migrates.

    The audit emit is best-effort: a missing audit-log singleton must not
    block authentication (the dashboard would fail closed on every
    request, locking the operator out of their own platform).
    """
    d = _load_user_directory()
    info = d.get(username)
    if not info:
        return None

    if "pass_hash" in info:
        if verify_password(password, info["pass_hash"]):
            return info["role"]
        return None

    if "pass" in info:
        if _secrets.compare_digest(info["pass"].encode(), password.encode()):
            _emit_plaintext_deprecation_event(username)
            return info["role"]
        return None

    return None


def _emit_plaintext_deprecation_event(username: str) -> None:
    """Append a one-shot ``auth.cred.plaintext.deprecated`` audit event so
    operators see the warning. Failures here are swallowed — auth must
    continue to function even if the audit writer is unavailable."""
    try:
        from core.models import AuditEntry

        from .deps import get_audit

        # ``write`` is async; we schedule it on the current loop if available,
        # otherwise we log a structlog warning so the deprecation is still
        # visible in operational logs.
        audit = get_audit()
        entry = AuditEntry(
            engagement_id="-",
            actor=username,
            action="auth.cred.plaintext.deprecated",
            target="",
            details={
                "migrate_via": "scripts/migrate_creds_v23.py",
                "removal_target": "v2.4",
            },
        )
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(audit.write(entry))
        else:
            _log.warning(
                "auth.cred.plaintext.deprecated",
                user=username,
                migrate_via="scripts/migrate_creds_v23.py",
                removal_target="v2.4",
            )
    except Exception as exc:  # pragma: no cover — defensive
        _log.warning("plaintext_deprecation_emit_failed", error=str(exc)[:120])


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
