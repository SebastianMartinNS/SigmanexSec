"""
sap_dashboard/backend/deps.py — Singletons & dependencies (auth, store, etc.)
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from core.audit_log import AuditLog
from core.executor import ToolExecutor
from core.session_store import SessionStore
from core.sudo_vault import SudoVault, get_sudo_vault


# ── Config ──────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "config.yaml"


@lru_cache(maxsize=1)
def get_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    return {}


def reload_config() -> dict:
    get_config.cache_clear()
    return get_config()


# ── Singletons ──────────────────────────────────────────────────────────────

_db_path  = os.environ.get("SESSION_DB_PATH", str(REPO_ROOT / "sessions" / "assessments.db"))
_log_path = os.environ.get("AUDIT_LOG_PATH",  str(REPO_ROOT / "logs" / "audit.jsonl"))

_store: Optional[SessionStore] = None
_audit: Optional[AuditLog] = None
_executor: Optional[ToolExecutor] = None


def get_store() -> SessionStore:
    global _store
    if _store is None:
        _store = SessionStore(_db_path)
    return _store


def get_audit() -> AuditLog:
    global _audit
    if _audit is None:
        _audit = AuditLog(_log_path)
    return _audit


def get_executor() -> ToolExecutor:
    global _executor
    if _executor is None:
        _executor = ToolExecutor(audit_log=get_audit())
    return _executor


def get_vault():
    """Return the active vault (local SudoVault or BrokerVaultProxy)."""
    return get_sudo_vault()


# ── Auth (HTTP Basic, dev-tier) ─────────────────────────────────────────────

_basic = HTTPBasic(auto_error=False)


def _expected_creds() -> tuple[str, str] | None:
    cfg = get_config().get("dashboard", {}).get("auth", {})
    user = os.environ.get("SAP_DASHBOARD_USER", cfg.get("user"))
    pwd  = os.environ.get("SAP_DASHBOARD_PASS", cfg.get("password"))
    if not user or not pwd:
        return None
    return user, pwd


def require_auth(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(_basic),
) -> str:
    """
    Authenticate the request via either:
      - signed HttpOnly session cookie (browser/SPA — preferred), OR
      - HTTP Basic credentials (API / tests / CLI clients).

    Returns the authenticated username.
    """
    expected = _expected_creds()
    if expected is None:
        # Dashboard auth not configured — refuse on every request to avoid
        # accidentally exposing the platform.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="dashboard auth not configured (set dashboard.auth.user/password)",
        )

    # 1) Session cookie path (preferred for browsers).
    from .security import (
        CSRF_COOKIE,
        SESSION_COOKIE,
        csrf_cookie_kwargs,
        refresh_session,
        session_cookie_kwargs,
        verify_session,
    )
    cookie_token = request.cookies.get(SESSION_COOKIE)
    if cookie_token:
        user = verify_session(cookie_token)
        if user:
            # Accept either the legacy single-user creds or any user listed
            # in the SAP_DASHBOARD_USERS RBAC directory (P2.3).
            from .rbac import lookup_role
            if (
                secrets.compare_digest(user.encode(), expected[0].encode())
                or lookup_role(user) is not None
            ):
                # Sliding refresh: re-sign cookie so the idle window resets
                # on every authenticated request, while ``iat`` (preserved
                # by ``refresh_session``) keeps the absolute cap.
                refreshed = refresh_session(cookie_token)
                if refreshed and refreshed != cookie_token:
                    response = getattr(request.state, "_response_for_cookie_refresh", None)
                    if response is None:
                        # Stash on request.state for a middleware to apply,
                        # but in practice the FastAPI Response dependency
                        # injection happens via the route signature. We fall
                        # back to setting on the active scope's response by
                        # using starlette's Response in the route. To keep
                        # the surface narrow, store the new token on
                        # request.state and let middleware emit it.
                        request.state.refresh_session_token = refreshed
                        request.state.refresh_session_secure = (
                            request.url.scheme == "https"
                            or request.headers.get("x-forwarded-proto", "").lower() == "https"
                        )
                return user
        # Cookie present but invalid -> reject with 401 (do not fall through).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired session",
        )

    # 2) HTTP Basic path (API/tests).
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="auth required",
            headers={"WWW-Authenticate": 'Basic realm="SAP"'},
        )
    user_ok = secrets.compare_digest(credentials.username.encode(), expected[0].encode())
    pass_ok = secrets.compare_digest(credentials.password.encode(), expected[1].encode())
    if user_ok and pass_ok:
        return credentials.username
    # Multi-user (P2.3) fall-back: try the directory.
    from .rbac import verify_user_password
    if verify_user_password(credentials.username, credentials.password):
        return credentials.username
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid credentials",
        headers={"WWW-Authenticate": 'Basic realm="SAP"'},
    )
