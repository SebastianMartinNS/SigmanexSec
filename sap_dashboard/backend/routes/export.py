"""
sap_dashboard/backend/routes/export.py — Engagement export bundle & context reset.

Endpoints
---------
GET  /api/engagements/{id}/export
    Stream a ZIP archive containing:
      - engagement.json            (Engagement model, scope, ROE, status)
      - hosts.json / findings.json / credentials.json (creds redacted by default)
      - audit.jsonl                (filtered audit entries for this engagement)
      - runs/<run_id>/events.jsonl (RunBroker history per run)
      - report.md                  (markdown summary, same content as /report)
    Query params:
      include_secrets=1            include decrypted credentials (default: 0 → redacted)

POST /api/engagements/{id}/reset
    Body: { wipe_findings, wipe_hosts, wipe_credentials, wipe_runs, wipe_audit, delete_engagement }
    Resets selected components for ONE engagement. Returns counters.

POST /api/system/reset
    Body: { confirm: "WIPE_ALL" }
    Wipe every engagement, all run sessions, audit log and reports.
    Requires the literal string `WIPE_ALL` as a kill-switch.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.models import AuditEntry

from ..deps import REPO_ROOT, get_audit, get_store, require_auth
from ..rbac import ROLE_ADMIN, require_role
from core.time_utils import utcnow as _sap_utcnow

router = APIRouter(prefix="/api", tags=["export"])

_RUNS_DIR     = REPO_ROOT / "sessions" / "runs"
_REPORTS_DIR  = REPO_ROOT / "sessions" / "reports"
_AUDIT_PATH   = Path(os.environ.get("AUDIT_LOG_PATH", REPO_ROOT / "logs" / "audit.jsonl"))


def _engagement_audit_lines(engagement_id: str) -> list[str]:
    if not _AUDIT_PATH.exists():
        return []
    out: list[str] = []
    with _AUDIT_PATH.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("engagement_id") == engagement_id:
                out.append(line)
    return out


def _engagement_run_dirs(engagement_id: str) -> list[Path]:
    """Locate run session dirs whose first event references this engagement_id."""
    matches: list[Path] = []
    if not _RUNS_DIR.exists():
        return matches
    for d in sorted(_RUNS_DIR.iterdir()):
        events = d / "events.jsonl"
        if not events.exists():
            continue
        try:
            with events.open("r", encoding="utf-8", errors="replace") as f:
                head = f.readline()
            if not head:
                continue
            obj = json.loads(head)
            if obj.get("engagement_id") == engagement_id:
                matches.append(d)
        except Exception:
            continue
    return matches


def _md_summary(eng, hosts, findings, creds, run_count: int, audit_count: int) -> str:
    lines = [
        f"# Pentest Report — {eng.name}",
        f"- Engagement ID: `{eng.id}`",
        f"- Client: {eng.client}",
        f"- Tester: {eng.tester or 'n/a'}",
        f"- Authorization: {eng.authorization_ref or 'n/a'}",
        f"- Status: {eng.status.value}",
        f"- Phase: {eng.current_phase.value}",
        f"- Generated: {_sap_utcnow().isoformat()}Z",
        "",
        "## Scope",
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
    lines += [
        "",
        f"## Credentials harvested: {len(creds)}",
        f"## Agent runs included: {run_count}",
        f"## Audit entries included: {audit_count}",
    ]
    return "\n".join(lines) + "\n"


def _zip_bundle(engagement_id: str, include_secrets: bool, eng, hosts, findings, creds) -> bytes:
    buf = io.BytesIO()
    audit_lines = _engagement_audit_lines(engagement_id)
    run_dirs = _engagement_run_dirs(engagement_id)

    md = _md_summary(eng, hosts, findings, creds, len(run_dirs), len(audit_lines))

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "engagement.json",
            json.dumps(eng.model_dump(mode="json"), indent=2, default=str),
        )
        zf.writestr(
            "hosts.json",
            json.dumps([h.model_dump(mode="json") for h in hosts], indent=2, default=str),
        )
        zf.writestr(
            "findings.json",
            json.dumps([f.model_dump(mode="json") for f in findings], indent=2, default=str),
        )

        cred_dump = []
        for c in creds:
            d = c.model_dump(mode="json")
            if not include_secrets:
                if d.get("password"):    d["password"]    = "[REDACTED]"
                if d.get("hash_value"):  d["hash_value"]  = "[REDACTED]"
            cred_dump.append(d)
        zf.writestr("credentials.json", json.dumps(cred_dump, indent=2, default=str))

        zf.writestr("audit.jsonl", "\n".join(audit_lines) + ("\n" if audit_lines else ""))

        for d in run_dirs:
            for sub in d.iterdir():
                if sub.is_file():
                    zf.write(sub, arcname=f"runs/{d.name}/{sub.name}")

        zf.writestr("report.md", md)
        zf.writestr(
            "MANIFEST.json",
            json.dumps({
                "engagement_id": engagement_id,
                "exported_at": _sap_utcnow().isoformat() + "Z",
                "include_secrets": include_secrets,
                "counts": {
                    "hosts": len(hosts),
                    "findings": len(findings),
                    "credentials": len(creds),
                    "runs": len(run_dirs),
                    "audit_entries": len(audit_lines),
                },
                "format_version": 1,
            }, indent=2),
        )
    buf.seek(0)
    return buf.getvalue()


@router.get("/engagements/{engagement_id}/export")
async def export_engagement(
    engagement_id: str,
    include_secrets: int = Query(0, ge=0, le=1),
    user: str = Depends(require_auth),
):
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")
    hosts    = await store.get_hosts(engagement_id)
    findings = await store.get_findings(engagement_id)
    creds    = await store.get_credentials(engagement_id)

    audit = get_audit()
    await audit.write(AuditEntry(
        engagement_id=engagement_id, actor=user, action="engagement_export",
        target=engagement_id,
        details={"include_secrets": bool(include_secrets), "format": "zip"},
    ))

    blob = _zip_bundle(engagement_id, bool(include_secrets), eng, hosts, findings, creds)
    ts = _sap_utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"engagement_{engagement_id[:8]}_{ts}.zip"
    return StreamingResponse(
        io.BytesIO(blob),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Reset endpoints ─────────────────────────────────────────────────────────

class ResetBody(BaseModel):
    wipe_findings: bool = False
    wipe_hosts: bool = False
    wipe_credentials: bool = False
    wipe_runs: bool = False
    wipe_audit: bool = False
    delete_engagement: bool = False


def _filter_audit_file(keep_predicate) -> int:
    """Rewrite audit file in place, keep only lines for which predicate(obj) is True.
    Returns number of removed lines."""
    if not _AUDIT_PATH.exists():
        return 0
    tmp = _AUDIT_PATH.with_suffix(".jsonl.tmp")
    removed = 0
    with _AUDIT_PATH.open("r", encoding="utf-8", errors="replace") as src, \
         tmp.open("w", encoding="utf-8") as dst:
        for line in src:
            s = line.rstrip("\n")
            if not s:
                continue
            try:
                obj = json.loads(s)
            except Exception:
                dst.write(line); continue
            if keep_predicate(obj):
                dst.write(line)
            else:
                removed += 1
    tmp.replace(_AUDIT_PATH)
    return removed


@router.post("/engagements/{engagement_id}/reset")
async def reset_engagement(
    engagement_id: str,
    body: ResetBody = Body(default=ResetBody()),
    user: str = Depends(require_role(ROLE_ADMIN)),
):
    store = get_store()
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="engagement not found")

    counters: dict[str, int] = {}

    if body.wipe_findings:
        counters["findings_deleted"]    = await store.delete_findings(engagement_id)
    if body.wipe_credentials:
        counters["credentials_deleted"] = await store.delete_credentials(engagement_id)
    if body.wipe_hosts:
        counters["hosts_deleted"]       = await store.delete_hosts(engagement_id)

    if body.wipe_runs:
        n = 0
        for d in _engagement_run_dirs(engagement_id):
            shutil.rmtree(d, ignore_errors=True)
            n += 1
        counters["run_dirs_deleted"] = n

    if body.wipe_audit:
        counters["audit_lines_removed"] = _filter_audit_file(
            lambda o: o.get("engagement_id") != engagement_id
        )

    if body.delete_engagement:
        ok = await store.delete_engagement(engagement_id)
        counters["engagement_deleted"] = 1 if ok else 0

    audit = get_audit()
    await audit.write(AuditEntry(
        engagement_id=engagement_id, actor=user, action="engagement_reset",
        target=engagement_id, details={**body.model_dump(), "counters": counters},
    ))
    return {"ok": True, "engagement_id": engagement_id, "counters": counters}


class SystemResetBody(BaseModel):
    confirm: str  # must be "WIPE_ALL"


@router.post("/system/reset")
async def reset_system(
    body: SystemResetBody, user: str = Depends(require_role(ROLE_ADMIN)),
):
    if body.confirm != "WIPE_ALL":
        raise HTTPException(status_code=400, detail='confirm must be the literal string "WIPE_ALL"')

    store = get_store()
    await store.init()

    engs = await store.list_engagements()
    eng_count = 0
    for e in engs:
        if await store.delete_engagement(e.id):
            eng_count += 1

    runs_removed = 0
    if _RUNS_DIR.exists():
        for d in _RUNS_DIR.iterdir():
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
                runs_removed += 1

    reports_removed = 0
    if _REPORTS_DIR.exists():
        for f in _REPORTS_DIR.iterdir():
            if f.is_file():
                f.unlink(missing_ok=True)
                reports_removed += 1

    audit_removed = 0
    if _AUDIT_PATH.exists():
        try:
            audit_removed = sum(1 for _ in _AUDIT_PATH.open("r", encoding="utf-8", errors="replace"))
        except Exception:
            audit_removed = -1
        _AUDIT_PATH.write_text("")

    audit = get_audit()
    await audit.write(AuditEntry(
        engagement_id="-", actor=user, action="system_reset", target="*",
        details={
            "engagements_deleted": eng_count,
            "run_dirs_deleted": runs_removed,
            "reports_deleted": reports_removed,
            "audit_lines_removed": audit_removed,
        },
    ))
    return {
        "ok": True,
        "engagements_deleted": eng_count,
        "run_dirs_deleted": runs_removed,
        "reports_deleted": reports_removed,
        "audit_lines_removed": audit_removed,
    }
