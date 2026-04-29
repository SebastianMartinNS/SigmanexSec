"""
sap_dashboard/backend/routes/settings.py — Runtime config view & live patch.

Patches are kept in-memory only (we don't rewrite the YAML on disk to avoid
mutating committed config). The dashboard surfaces this state for visibility.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..deps import get_config, require_auth
from ..schemas import SettingsPatch, SettingsView

router = APIRouter(prefix="/api/settings", tags=["settings"])

_OVERLAY: dict = {}  # in-memory diff applied on top of disk config


def _merged() -> dict:
    base = dict(get_config())
    for section, patch in _OVERLAY.items():
        merged = dict(base.get(section, {}))
        merged.update(patch)
        base[section] = merged
    return base


@router.get("", response_model=SettingsView)
async def get_settings(_user: str = Depends(require_auth)):
    cfg = _merged()
    return SettingsView(
        llm=cfg.get("llm", {}),
        agent=cfg.get("agent", {}),
        executor=cfg.get("executor", {}),
        sudo=cfg.get("sudo", {}),
        mcp_servers=["engagement", "recon", "exploit", "blueteam", "parrot"],
    )


@router.patch("", response_model=SettingsView)
async def patch_settings(body: SettingsPatch, _user: str = Depends(require_auth)):
    if body.section not in ("llm", "agent", "executor", "sudo"):
        raise HTTPException(status_code=400, detail="unknown section")
    _OVERLAY.setdefault(body.section, {})[body.key] = body.value
    return await get_settings()
