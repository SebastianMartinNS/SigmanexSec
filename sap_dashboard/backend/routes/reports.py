"""
sap_dashboard/backend/routes/reports.py — Report generation & download.

A real implementation would render Markdown/HTML/PDF from the engagement
data; v1 returns a minimal Markdown summary on demand.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from ..deps import REPO_ROOT, get_store, require_auth
from core.time_utils import utcnow as _sap_utcnow

router = APIRouter(prefix="/api", tags=["reports"])

_REPORTS_DIR = REPO_ROOT / "sessions" / "reports"
_REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _md_summary(eng, hosts, findings, creds) -> str:
    lines = [
        f"# Pentest Report — {eng.name}",
        f"- Client: {eng.client}",
        f"- Tester: {eng.tester or 'n/a'}",
        f"- Authorization: {eng.authorization_ref or 'n/a'}",
        f"- Status: {eng.status.value}",
        f"- Phase: {eng.current_phase.value}",
        f"- Generated: {_sap_utcnow().isoformat()}Z",
        "",
        f"## Scope",
        f"- CIDRs: {', '.join(eng.scope_cidrs) or 'none'}",
        f"- Domains: {', '.join(eng.scope_domains) or 'none'}",
        f"- URLs: {', '.join(eng.scope_urls) or 'none'}",
        "",
        f"## Hosts ({len(hosts)})",
    ]
    for h in hosts:
        lines.append(f"- {h.ip} ({h.hostname or '-'}) — {len(h.services)} services")
    lines += ["", f"## Findings ({len(findings)})"]
    for f in findings:
        lines.append(f"- [{f.severity.value.upper()}] {f.title}")
    lines += ["", f"## Credentials harvested: {len(creds)}"]
    return "\n".join(lines) + "\n"


@router.post("/engagements/{engagement_id}/report")
async def generate_report(engagement_id: str, _user: str = Depends(require_auth)):
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    hosts = await store.get_hosts(engagement_id)
    findings = await store.get_findings(engagement_id)
    creds = await store.get_credentials(engagement_id)

    md = _md_summary(eng, hosts, findings, creds)
    ts = _sap_utcnow().strftime("%Y%m%dT%H%M%SZ")
    out = _REPORTS_DIR / f"{engagement_id}_{ts}.md"
    out.write_text(md)
    return {"report_id": out.stem, "path": str(out), "format": "md"}


@router.get("/reports/{report_id}.md", response_class=PlainTextResponse)
async def download_md(report_id: str, _user: str = Depends(require_auth)):
    p = _REPORTS_DIR / f"{report_id}.md"
    if not p.exists():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(p, media_type="text/markdown")
