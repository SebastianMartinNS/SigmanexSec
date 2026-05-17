"""
sap_dashboard/backend/routes/outputs.py — Tool Output Store viewer.

Surface persisted tool outputs (ToolOutputStore) to the dashboard UI so
operators can inspect the FULL stdout/stderr/artifacts that were truncated
in the live stream. Backed by the SQLite ``tool_outputs`` index plus the
filesystem blobs under ``sessions/runs/{run_id}/tool_outputs/{call_id}/``.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from core.tool_output_store import get_tool_output_store

from ..deps import require_auth
from ..rbac import ROLE_VIEWER, require_role

router = APIRouter(
    prefix="/api",
    tags=["outputs"],
    # ToolOutputStore is read-only data; any authenticated viewer can browse it.
    dependencies=[Depends(require_role(ROLE_VIEWER))],
)


# ── Listing ────────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/outputs")
async def list_run_outputs(
    run_id: str,
    tool: str | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    _user: str = Depends(require_auth),
) -> dict:
    store = get_tool_output_store()
    refs = await store.list(run_id=run_id, tool=tool, limit=limit)
    return {"run_id": run_id, "count": len(refs), "items": [r.to_dict() for r in refs]}


@router.get("/engagements/{engagement_id}/outputs")
async def list_engagement_outputs(
    engagement_id: str,
    tool: str | None = Query(None),
    limit: int = Query(200, ge=1, le=2000),
    _user: str = Depends(require_auth),
) -> dict:
    store = get_tool_output_store()
    refs = await store.list(engagement_id=engagement_id, tool=tool, limit=limit)
    return {
        "engagement_id": engagement_id,
        "count": len(refs),
        "items": [r.to_dict() for r in refs],
    }


# ── Read content (range-friendly) ──────────────────────────────────────────

@router.get("/outputs/{call_id}")
async def get_output_meta(
    call_id: str, _user: str = Depends(require_auth),
) -> dict:
    store = get_tool_output_store()
    ref = await store.get(call_id)
    if ref is None:
        raise HTTPException(status_code=404, detail="call_id not found")
    return ref.to_dict()


@router.get("/outputs/{call_id}/artifacts")
async def list_artifacts(
    call_id: str, _user: str = Depends(require_auth),
) -> dict:
    store = get_tool_output_store()
    ref = await store.get(call_id)
    if ref is None:
        raise HTTPException(status_code=404, detail="call_id not found")
    adir = Path(ref.artifacts_dir or "")
    if not adir.exists():
        return {"call_id": call_id, "files": []}
    files = []
    for p in sorted(adir.rglob("*")):
        if p.is_file():
            try:
                files.append({
                    "name": str(p.relative_to(adir)),
                    "size": p.stat().st_size,
                })
            except Exception:
                continue
    return {"call_id": call_id, "files": files}


@router.get("/outputs/{call_id}/artifacts/{filename:path}")
async def download_artifact(
    call_id: str, filename: str, _user: str = Depends(require_auth),
):
    store = get_tool_output_store()
    ref = await store.get(call_id)
    if ref is None:
        raise HTTPException(status_code=404, detail="call_id not found")
    base = Path(ref.artifacts_dir or "").resolve()
    if not base.exists():
        raise HTTPException(status_code=404, detail="no artifacts")
    target = (base / filename).resolve()
    # Path-traversal guard: target must remain under base
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid filename") from exc
    if not target.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(str(target), filename=target.name)


@router.get(
    "/outputs/{call_id}/{kind}",
    response_class=PlainTextResponse,
)
async def get_output_body(
    call_id: str,
    kind: str,
    head: int | None = Query(None, ge=0),
    tail: int | None = Query(None, ge=0),
    offset: int | None = Query(None, ge=0),
    length: int | None = Query(None, ge=0),
    _user: str = Depends(require_auth),
) -> str:
    if kind not in ("stdout", "stderr"):
        raise HTTPException(status_code=400, detail="kind must be stdout|stderr")
    store = get_tool_output_store()
    try:
        data = await store.read(
            call_id, kind, head=head, tail=tail, offset=offset, length=length,
        )
    except (FileNotFoundError, KeyError) as exc:
        raise HTTPException(status_code=404, detail="call_id or stream not found") from exc
    return data.decode("utf-8", errors="replace")
