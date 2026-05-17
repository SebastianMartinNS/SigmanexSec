"""
sap_dashboard/backend/routes/sudo.py — Sudo Vault control plane.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from core.models import AuditEntry
from core.rate_limiter import get_rate_limiter
from core.sudo_broker import BrokerUnavailable
from core.sudo_vault import SudoFailed

from ..deps import get_audit, get_vault, require_auth
from ..rbac import ROLE_OPERATOR, require_role
from ..schemas import SudoStatus, SudoUnlockBody
from ..security import rotate_csrf

router = APIRouter(
    prefix="/api/sudo",
    tags=["sudo"],
    # Every sudo control-plane operation (status/unlock/lock/heartbeat)
    # implies the user can drive privileged tools. operator is the floor.
    dependencies=[Depends(require_role(ROLE_OPERATOR))],
)


# P1.7: cross-process rate-limit + lockout, shared with all uvicorn workers.
def _rate_limit(actor: str) -> None:
    limiter = get_rate_limiter()
    decision = limiter.check(
        f"sudo_unlock:{actor}",
        window_s=60,
        max_attempts=2,           # 2 unlocks/min/operator
        max_failures=5,           # 5 wrong passwords ⇒ 15-min lockout
        lockout_s=900,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail=f"too many sudo unlock attempts ({decision.reason}); retry in {decision.retry_after_s}s",
            headers={"Retry-After": str(decision.retry_after_s)},
        )


def _status_payload(s: dict) -> SudoStatus:
    # Filter unknown keys (proxy may return extras).
    allowed = {"locked", "expires_at_monotonic", "ttl_remaining_seconds",
               "last_use_monotonic", "failures", "unlock_count"}
    return SudoStatus(**{k: v for k, v in s.items() if k in allowed})


@router.get("/status", response_model=SudoStatus)
async def status_endpoint(_user: str = Depends(require_auth)):
    v = get_vault()
    try:
        s = await v.status()
    except BrokerUnavailable as e:
        raise HTTPException(status_code=503, detail=f"sudo broker unavailable: {e}") from e
    return _status_payload(s)


@router.post("/unlock", response_model=SudoStatus)
async def unlock_endpoint(
    body: SudoUnlockBody,
    request: Request,
    response: Response,
    user: str = Depends(require_auth),
):
    _rate_limit(user)
    v = get_vault()
    limiter = get_rate_limiter()
    rl_key = f"sudo_unlock:{user}"
    try:
        await v.unlock(body.password, ttl_seconds=body.ttl_seconds)
    except SudoFailed as e:
        limiter.record_failure(rl_key, max_failures=5, lockout_s=900)
        # Audit failures (no password material is logged).
        await get_audit().write(AuditEntry(
            engagement_id="-", actor=user,
            action="sudo_unlock_failed", details={"error": str(e)},
        ))
        raise HTTPException(status_code=400, detail=str(e)) from e
    except BrokerUnavailable as e:
        raise HTTPException(status_code=503, detail=f"sudo broker unavailable: {e}") from e

    limiter.record_success(rl_key)

    await get_audit().write(AuditEntry(
        engagement_id="-", actor=user,
        action="sudo_unlock", details={"ttl_seconds": body.ttl_seconds},
    ))
    # Phase 4: rotate the CSRF token after a privileged mutation so a
    # stolen-and-replayed token cannot be reused on a follow-up request.
    rotate_csrf(request, response)
    return _status_payload(await v.status())


@router.delete("", response_model=SudoStatus)
async def lock_endpoint(
    request: Request,
    response: Response,
    user: str = Depends(require_auth),
):
    v = get_vault()
    try:
        await v.lock()
    except BrokerUnavailable as e:
        raise HTTPException(status_code=503, detail=f"sudo broker unavailable: {e}") from e
    await get_audit().write(AuditEntry(
        engagement_id="-", actor=user, action="sudo_lock", details={},
    ))
    rotate_csrf(request, response)
    return _status_payload(await v.status())


@router.post("/heartbeat", response_model=SudoStatus)
async def heartbeat_endpoint(_user: str = Depends(require_auth)):
    """Reset the inactivity timer; called periodically by the dashboard UI."""
    v = get_vault()
    try:
        if hasattr(v, "heartbeat"):
            s = await v.heartbeat()
        else:
            # Local SudoVault: a successful borrow updates last_use too.
            if await v.is_unlocked():
                await v.record_success()
            s = await v.status()
    except BrokerUnavailable as e:
        raise HTTPException(status_code=503, detail=f"sudo broker unavailable: {e}") from e
    return _status_payload(s)
