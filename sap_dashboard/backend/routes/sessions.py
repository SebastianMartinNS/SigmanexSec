"""
sap_dashboard/backend/routes/sessions.py — Interactive PTY session API.

Wraps the InteractiveSessionManager (core/interactive_session.py) with a
small REST surface so the dashboard UI can spawn, drive and observe
long-lived offensive tools (msfconsole, evil-winrm, sqlmap, ...).

WebSocket support is intentionally omitted in v1; the UI polls
``GET /api/sessions/{id}/read`` every 1-2s for fresh output. This avoids
extra auth complexity (Basic auth doesn't carry over WS handshakes
cleanly with browsers) while keeping the protocol identical to what the
LLM sees via MCP.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.interactive_session import (
    SessionDead,
    SessionError,
    SessionLimitReached,
    SessionNotFound,
    get_manager,
)
from core.scope_validator import ScopeValidator

from ..deps import get_store, require_auth
from ..rbac import ROLE_OPERATOR, require_role

router = APIRouter(
    prefix="/api/sessions",
    tags=["sessions"],
    # Interactive PTY sessions spawn offensive tools — operator floor.
    dependencies=[Depends(require_role(ROLE_OPERATOR))],
)


# ── Request models ────────────────────────────────────────────────────────

class StartReq(BaseModel):
    tool: str = Field(..., description="catalog descriptor name")
    engagement_id: str
    args: dict = Field(default_factory=dict)


class SendReq(BaseModel):
    text: str
    expect_prompt: str | None = None
    timeout: float = 15.0


class ReadReq(BaseModel):
    timeout: float = 5.0


# ── Helpers ───────────────────────────────────────────────────────────────

async def _scope_for(engagement_id: str) -> ScopeValidator | None:
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        return None
    return ScopeValidator(
        cidrs=eng.scope_cidrs, domains=eng.scope_domains,
        urls=eng.scope_urls, engagement_id=engagement_id,
    )


# ── Routes ────────────────────────────────────────────────────────────────

@router.get("")
async def list_sessions(
    engagement_id: str = "", _user: str = Depends(require_auth),
):
    return {"sessions": get_manager().list(engagement_id or None)}


@router.post("")
async def start_session(req: StartReq, user: str = Depends(require_auth)):
    scope = await _scope_for(req.engagement_id)
    if scope is None:
        raise HTTPException(404, f"engagement '{req.engagement_id}' not found")
    try:
        return await get_manager().start(
            tool_name=req.tool, engagement_id=req.engagement_id,
            args=req.args, actor=f"user:{user}", scope=scope,
        )
    except SessionLimitReached as e:
        raise HTTPException(429, f"limit: {e}") from e
    except SessionError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{session_id}/send")
async def send_session(
    session_id: str, req: SendReq, _user: str = Depends(require_auth),
):
    try:
        return await get_manager().send(
            session_id=session_id, text=req.text,
            expect_prompt=req.expect_prompt, timeout=req.timeout,
        )
    except SessionNotFound as e:
        raise HTTPException(404, str(e)) from e
    except SessionDead as e:
        raise HTTPException(410, str(e)) from e
    except SessionError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/{session_id}/read")
async def read_session(
    session_id: str, req: ReadReq, _user: str = Depends(require_auth),
):
    try:
        return await get_manager().read(session_id, timeout=req.timeout)
    except SessionNotFound as e:
        raise HTTPException(404, str(e)) from e
    except SessionError as e:
        raise HTTPException(400, str(e)) from e


@router.delete("/{session_id}")
async def close_session(session_id: str, _user: str = Depends(require_auth)):
    try:
        return await get_manager().close(session_id)
    except SessionNotFound as e:
        raise HTTPException(404, str(e)) from e
    except SessionError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/reap")
async def reap_idle(_user: str = Depends(require_auth)):
    """Manually trigger TTL cleanup of idle sessions."""
    n = await get_manager().reap_idle()
    return {"closed": n}
