"""
sap_dashboard/backend/routes/auth.py — Cookie-based login/logout (P0).
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from core.models import AuditEntry
from core.rate_limiter import get_rate_limiter

from ..deps import _expected_creds, get_audit, require_auth
from ..rbac import lookup_role, verify_user_password
from ..security import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    csrf_cookie_kwargs,
    issue_session,
    new_csrf_token,
    session_cookie_kwargs,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _is_secure(request: Request) -> bool:
    if request.url.scheme == "https":
        return True
    return request.headers.get("x-forwarded-proto", "").lower() == "https"


@router.post("/login")
async def login(request: Request, response: Response):
    """Exchange username/password for a session + CSRF cookie pair.

    Body: {"username": "...", "password": "..."} (JSON).
    Sets HttpOnly session cookie and a JS-readable CSRF cookie.
    """
    expected = _expected_creds()
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="dashboard auth not configured",
        )
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc
    user = str(body.get("username", ""))
    pwd  = str(body.get("password", ""))

    # Cross-process throttle + lockout (P1.7).
    ip = request.client.host if request.client else "?"
    rl_key = f"login:{ip}"
    limiter = get_rate_limiter()
    decision = limiter.check(
        rl_key, window_s=60, max_attempts=5, max_failures=10, lockout_s=900,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=f"too many login attempts ({decision.reason}); retry in {decision.retry_after_s}s",
            headers={"Retry-After": str(decision.retry_after_s)},
        )

    user_ok = secrets.compare_digest(user.encode(), expected[0].encode())
    pass_ok = secrets.compare_digest(pwd.encode(),  expected[1].encode())
    role = verify_user_password(user, pwd) if user else None
    if not ((user_ok and pass_ok) or role):
        limiter.record_failure(rl_key, max_failures=10, lockout_s=900)
        try:
            await get_audit().write(AuditEntry(
                engagement_id="-", actor=user or "?",
                action="dashboard_login_failed",
                details={"ip": ip},
            ))
        except Exception:  # never block auth flow on audit failure
            pass
        raise HTTPException(status_code=401, detail="invalid credentials")

    limiter.record_success(rl_key)

    secure = _is_secure(request)
    response.set_cookie(value=issue_session(user), **session_cookie_kwargs(secure))
    response.set_cookie(value=new_csrf_token(),    **csrf_cookie_kwargs(secure))

    try:
        await get_audit().write(AuditEntry(
            engagement_id="-", actor=user, action="dashboard_login",
            details={"ip": ip, "role": lookup_role(user) or "viewer"},
        ))
    except Exception:
        pass
    return {"ok": True, "username": user, "role": lookup_role(user) or "viewer"}


@router.post("/logout")
async def logout(request: Request, response: Response, _user: str = Depends(require_auth)):
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
async def me(user: str = Depends(require_auth)):
    return {"username": user, "role": lookup_role(user) or "viewer"}
