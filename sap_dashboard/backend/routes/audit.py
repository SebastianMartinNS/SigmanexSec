"""
sap_dashboard/backend/routes/audit.py — Read + tail of logs/audit.jsonl.

Esposto per dare visibilità anche alle attività MCP scatenate dalla WebUI di
llama.cpp (che bypassano l'Orchestrator e quindi il RunBroker).
"""
from __future__ import annotations

import asyncio
import json
import os
from base64 import b64decode
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status

from ..deps import REPO_ROOT, _expected_creds, require_auth

router = APIRouter(prefix="/api/audit", tags=["audit"])


# Phase 4: per-IP cap on concurrent /api/audit/ws connections to keep a
# single misbehaving client from exhausting the writer task pool. Override
# via ``SAP_DASHBOARD_WS_PER_IP`` (default 4 concurrent sockets per peer).
_WS_CONN_LOCK = asyncio.Lock()
_WS_CONN_COUNT: dict[str, int] = {}


def _ws_per_ip_cap() -> int:
    try:
        v = int(os.environ.get("SAP_DASHBOARD_WS_PER_IP", "4"))
    except ValueError:
        v = 4
    return max(1, v)


def _audit_path() -> Path:
    return Path(os.environ.get("AUDIT_LOG_PATH", str(REPO_ROOT / "logs" / "audit.jsonl")))


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip()]


@router.get("")
async def list_audit(
    engagement_id: Optional[str] = Query(None),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    _user: str = Depends(require_auth),
):
    """Ultime ``limit`` voci di audit, opzionalmente filtrate."""
    lines = _read_lines(_audit_path())
    out: list[dict] = []
    for ln in reversed(lines):
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        if engagement_id and obj.get("engagement_id") != engagement_id:
            continue
        if actor and obj.get("actor") != actor:
            continue
        if action and obj.get("action") != action:
            continue
        out.append(obj)
        if len(out) >= limit:
            break
    out.reverse()
    return out


@router.get("/loop-counters")
async def loop_counters(
    engagement_id: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
    limit: int = Query(2000, ge=1, le=20000),
    _user: str = Depends(require_auth),
):
    """Counter ``tool_call_loop_detected`` per engagement/run/tool.

    Conta le decisioni ``decision.repetition_blocked`` emesse
    dall'orchestrator quando il loop-breaker si attiva. Utile per
    osservare in tempo reale tool che il modello sta richiamando in
    loop con argomenti identici.
    """
    lines = _read_lines(_audit_path())
    by_engagement: dict[str, int] = {}
    by_run: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    recent: list[dict] = []
    total = 0
    # Walk newest → oldest, cap at `limit` entries scanned.
    for ln in reversed(lines[-limit:]):
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        if obj.get("action") != "decision.repetition_blocked":
            continue
        eid = obj.get("engagement_id") or ""
        if engagement_id and eid != engagement_id:
            continue
        details = obj.get("details") or {}
        rid = (details.get("run_id") or "") if isinstance(details, dict) else ""
        if run_id and rid != run_id:
            continue
        tool = obj.get("target") or (details.get("tool") if isinstance(details, dict) else "") or "?"
        total += 1
        by_engagement[eid] = by_engagement.get(eid, 0) + 1
        by_run[rid] = by_run.get(rid, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1
        if len(recent) < 50:
            recent.append(obj)
    return {
        "tool_call_loop_detected": total,
        "by_engagement": by_engagement,
        "by_run": by_run,
        "by_tool": by_tool,
        "recent": recent,
    }


@router.websocket("/ws")
async def ws_audit(websocket: WebSocket):
    """
    Streaming live di logs/audit.jsonl. Il client manda prima un frame
    ``{"type":"auth","token":"<base64 user:pass>"}``.
    """
    peer = websocket.client.host if websocket.client else "?"
    cap = _ws_per_ip_cap()
    async with _WS_CONN_LOCK:
        if _WS_CONN_COUNT.get(peer, 0) >= cap:
            # Refuse the handshake outright (1013 Try Again Later); we
            # have not called ``accept()`` yet so the peer sees a clean
            # rejection rather than an authenticated socket.
            await websocket.close(code=1013)
            return
        _WS_CONN_COUNT[peer] = _WS_CONN_COUNT.get(peer, 0) + 1
    try:
        await websocket.accept()
        try:
            # Tightened from 10s → 3s (Phase 4): legitimate clients send the
            # auth frame immediately after the open handshake; longer windows
            # only help slow scanners hold connection slots.
            auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=3)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        expected = _expected_creds()
        if not expected or auth_msg.get("type") != "auth":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        try:
            u, p = b64decode(auth_msg.get("token", "").encode()).decode().split(":", 1)
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        if (u, p) != expected:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

        # Replay degli ultimi 50 record per dare contesto al client.
        history = _read_lines(path)[-50:]
        for ln in history:
            try:
                await websocket.send_json(json.loads(ln))
            except Exception:
                pass

        # Tail-follow: poll incrementale dell'offset di byte.
        try:
            with open(path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(0.5)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        await websocket.send_json(json.loads(line))
                    except Exception:
                        continue
        except WebSocketDisconnect:
            return
        except Exception:
            try:
                await websocket.close()
            except Exception:
                pass
    finally:
        async with _WS_CONN_LOCK:
            n = _WS_CONN_COUNT.get(peer, 0) - 1
            if n <= 0:
                _WS_CONN_COUNT.pop(peer, None)
            else:
                _WS_CONN_COUNT[peer] = n

