"""
sap_dashboard/backend/routes/parrot.py — Parrot tool catalogue read API.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from core.parrot_catalog import (
    binary_available,
    gap_report,
    get_descriptor,
    list_by_category,
    load_catalog,
)

from ..deps import require_auth
from ..rbac import ROLE_VIEWER, require_role

router = APIRouter(
    prefix="/api/parrot",
    tags=["parrot"],
    # Browsing the tool catalogue is read-only; viewer is sufficient.
    dependencies=[Depends(require_role(ROLE_VIEWER))],
)


@router.get("/tools")
async def list_tools(_user: str = Depends(require_auth)):
    cat = load_catalog()
    rows = []
    for d in cat:
        rows.append({
            "name": d.get("name"),
            "binary": d.get("binary"),
            "category": d.get("category"),
            "description": d.get("description", ""),
            "requires_sudo": bool(d.get("requires_sudo")),
            "available": binary_available(d.get("binary", d.get("name", ""))),
            "mitre": d.get("mitre", []),
            "interactive": bool(d.get("interactive")),
            "risk_level": d.get("risk_level", "unknown"),
            "when": d.get("when", ""),
        })
    return {"by_category": list_by_category(), "tools": rows, "gap": gap_report()}


@router.get("/tools/{name}")
async def get_tool(name: str, _user: str = Depends(require_auth)):
    d = get_descriptor(name)
    if not d:
        raise HTTPException(status_code=404, detail=f"unknown tool '{name}'")
    return {**d, "available": binary_available(d.get("binary", name))}
