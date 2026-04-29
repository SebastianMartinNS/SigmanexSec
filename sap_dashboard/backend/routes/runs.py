"""
sap_dashboard/backend/routes/runs.py — Agent run REST + WebSocket.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status,
)

from ..deps import require_auth
from ..run_manager import get_runs
from ..schemas import ApprovalDecisionBody, RunControl, RunStartBody, RunStatus
from ..ws import get_broker

router = APIRouter(prefix="/api", tags=["runs"])


@router.post("/engagements/{engagement_id}/run", response_model=RunStatus)
async def start_run(
    engagement_id: str, body: RunStartBody, _user: str = Depends(require_auth)
):
    mgr = get_runs()
    handle = await mgr.start(
        engagement_id=engagement_id,
        objective=body.objective,
        mode=body.mode,
        max_iterations=body.max_iterations,
    )
    return RunStatus(**handle.to_dict())


@router.get("/runs/{run_id}", response_model=RunStatus)
async def get_run(run_id: str, _user: str = Depends(require_auth)):
    h = get_runs().get(run_id)
    if not h:
        raise HTTPException(status_code=404, detail="run not found")
    return RunStatus(**h.to_dict())


@router.patch("/runs/{run_id}", response_model=RunStatus)
async def control_run(run_id: str, body: RunControl, _user: str = Depends(require_auth)):
    try:
        h = await get_runs().control(run_id, body.action)
    except KeyError:
        raise HTTPException(status_code=404, detail="run not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return RunStatus(**h.to_dict())


@router.post("/runs/{run_id}/approve")
async def approve_run(
    run_id: str, body: ApprovalDecisionBody, user: str = Depends(require_auth)
):
    if body.decision not in ("allow", "deny"):
        raise HTTPException(status_code=400, detail="decision must be allow|deny")
    ok = await get_runs().approve(
        run_id, body.gate_id, body.decision, reason=body.reason, user=user,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="gate not found or already resolved")
    return {"ok": True}


@router.get("/runs/{run_id}/events")
async def get_events_history(
    run_id: str, from_seq: int = 0, _user: str = Depends(require_auth),
):
    return get_broker().history(run_id, from_seq=from_seq)


# ── WebSocket: live event stream ────────────────────────────────────────────

@router.websocket("/runs/{run_id}/events/ws")
async def ws_events(websocket: WebSocket, run_id: str, from_seq: int = 0):
    """
    Cookie-authenticated WebSocket. The browser inherits the HttpOnly
    session cookie set by /api/auth/login on the upgrade request. Legacy
    HTTP Basic clients may also use the standard Authorization header.
    """
    # Authenticate BEFORE accepting the upgrade.
    user: Optional[str] = None

    # Path A: signed session cookie.
    from ..security import SESSION_COOKIE, verify_session
    from ..deps import _expected_creds
    expected = _expected_creds()
    if expected is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    cookie_tok = websocket.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidate = verify_session(cookie_tok)
        if candidate and candidate == expected[0]:
            user = candidate

    # Path B: HTTP Basic via Authorization header (CLI / tests).
    if user is None:
        from base64 import b64decode
        auth = websocket.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                u, p = b64decode(auth.split(" ", 1)[1].encode()).decode().split(":", 1)
                if u == expected[0] and p == expected[1]:
                    user = u
            except Exception:
                pass

    if user is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    broker = get_broker()
    queue = broker.subscribe(run_id, from_seq=from_seq)
    try:
        while True:
            ev = await queue.get()
            await websocket.send_json(ev)
    except WebSocketDisconnect:
        pass
    finally:
        broker.unsubscribe(run_id, queue)
