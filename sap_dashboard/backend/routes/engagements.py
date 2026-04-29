"""
sap_dashboard/backend/routes/engagements.py — Engagement CRUD routes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from core.models import Engagement, EngagementStatus, Phase

from ..deps import get_store, require_auth
from ..schemas import EngagementCreateBody, EngagementPatch, EngagementSummary

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


@router.get("", response_model=list[EngagementSummary])
async def list_engagements(_user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    engs = await store.list_engagements()
    return [
        EngagementSummary(
            id=e.id, name=e.name, client=e.client,
            status=e.status.value, current_phase=e.current_phase.value,
            created_at=e.created_at,
        )
        for e in engs
    ]


@router.post("", response_model=Engagement)
async def create_engagement(body: EngagementCreateBody, _user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    eng = Engagement(**body.model_dump())
    return await store.create_engagement(eng)


@router.get("/{engagement_id}", response_model=Engagement)
async def get_engagement(engagement_id: str, _user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    return eng


@router.patch("/{engagement_id}", response_model=Engagement)
async def patch_engagement(
    engagement_id: str, body: EngagementPatch, _user: str = Depends(require_auth)
):
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    if body.status is not None:
        try:
            await store.update_engagement_status(engagement_id, EngagementStatus(body.status))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid status: {e}")
    if body.current_phase is not None:
        try:
            await store.update_engagement_phase(engagement_id, Phase(body.current_phase))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"invalid phase: {e}")
    return await store.get_engagement(engagement_id)


@router.get("/{engagement_id}/hosts")
async def list_hosts(engagement_id: str, _user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    return await store.get_hosts(engagement_id)


@router.get("/{engagement_id}/findings")
async def list_findings(engagement_id: str, _user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    return await store.get_findings(engagement_id)


@router.get("/{engagement_id}/credentials")
async def list_credentials(
    engagement_id: str, user: str = Depends(require_auth)
):
    store = get_store()
    await store.init()
    creds = await store.get_credentials(engagement_id)
    # Audit credential reads
    from core.models import AuditEntry
    from ..deps import get_audit
    await get_audit().write(AuditEntry(
        engagement_id=engagement_id,
        actor=user,
        action="credentials_view",
        details={"count": len(creds)},
    ))
    return creds
