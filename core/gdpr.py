"""
core/gdpr.py — GDPR / privacy-by-design data lifecycle helpers (P2.2).

Two responsibilities:

1. **Purge a single engagement** on operator request (Art. 17 — right to
   erasure). Removes everything with that engagement_id from the SQLite
   store, the tool-output store (rows + on-disk files), audit log lines,
   and report files. The audit log is rewritten preserving the BLAKE2b
   hash chain so verifiers continue to accept the file.

2. **Apply a retention policy** across the full state directory. Default
   180 days for tool outputs and audit log; engagements keep their high-
   level metadata indefinitely (operator must run a purge to drop them).

Both operations are explicitly logged to the audit log themselves so the
deletion is traceable.

CLI is wired in `cli.py` — `python cli.py gdpr ...`.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.audit_log import AuditLog
from core.models import AuditEntry
from core.paths import audit_log_path, reports_dir, sessions_dir
from core.session_store import SessionStore


@dataclass
class PurgeResult:
    engagement_id: str
    deleted_findings: int = 0
    deleted_credentials: int = 0
    deleted_hosts: int = 0
    deleted_engagement: bool = False
    deleted_audit_lines: int = 0
    deleted_report_files: int = 0
    deleted_tool_output_rows: int = 0
    deleted_tool_output_dirs: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class RetentionResult:
    audit_lines_removed: int = 0
    audit_chain_rewritten: bool = False
    tool_output_rows_removed: int = 0
    tool_output_dirs_removed: int = 0


# ──────────────────────────────────────────────────────────────────────────
# Per-engagement purge
# ──────────────────────────────────────────────────────────────────────────

async def purge_engagement(
    engagement_id: str,
    *,
    db_path: Optional[str] = None,
    audit_path: Optional[str] = None,
    reports_path: Optional[str] = None,
    actor: str = "operator",
    reason: str = "gdpr_request",
) -> PurgeResult:
    """Delete every record tied to ``engagement_id``.

    The deletion is recorded in the audit log AFTER the data has been
    removed (so the proof of erasure survives). The hash chain is
    preserved by rewriting the file in place when audit lines are removed.
    """
    if not engagement_id or "/" in engagement_id or ".." in engagement_id:
        raise ValueError("invalid engagement_id")

    result = PurgeResult(engagement_id=engagement_id)

    # 1. SQLite store — engagements + child tables.
    store = SessionStore(db_path or str(sessions_dir() / "assessments.db"))
    await store.init()
    try:
        result.deleted_findings    = await store.delete_findings(engagement_id)
        result.deleted_credentials = await store.delete_credentials(engagement_id)
        result.deleted_hosts       = await store.delete_hosts(engagement_id)
        result.deleted_engagement  = await store.delete_engagement(engagement_id)
    except Exception as exc:
        result.errors.append(f"session_store: {exc}")

    # 2. Tool output store (rows + on-disk files for the engagement).
    try:
        from core.tool_output_store import get_tool_output_store
        tos = get_tool_output_store()
        if hasattr(tos, "delete_engagement"):
            stats = await tos.delete_engagement(engagement_id)
            result.deleted_tool_output_rows = stats.get("deleted_rows", 0)
            result.deleted_tool_output_dirs = stats.get("deleted_dirs", 0)
        else:
            # Fallback: best-effort directory wipe.
            run_dir = sessions_dir() / "runs"
            if run_dir.exists():
                for child in run_dir.glob(f"*{engagement_id}*"):
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                        result.deleted_tool_output_dirs += 1
    except Exception as exc:
        result.errors.append(f"tool_output_store: {exc}")

    # 3. Report files.
    try:
        rdir = Path(reports_path) if reports_path else reports_dir()
        if rdir.exists():
            for f in rdir.glob(f"{engagement_id}*"):
                try:
                    f.unlink()
                    result.deleted_report_files += 1
                except OSError as exc:
                    result.errors.append(f"reports {f.name}: {exc}")
    except Exception as exc:
        result.errors.append(f"reports: {exc}")

    # 4. Audit log: drop matching lines and rewrite the chain.
    try:
        ap = Path(audit_path) if audit_path else audit_log_path()
        if ap.exists():
            removed = _audit_purge_engagement(ap, engagement_id)
            result.deleted_audit_lines = removed
    except Exception as exc:
        result.errors.append(f"audit_log: {exc}")

    # 5. Audit the purge itself (recorded against `engagement_id="-"` so it
    #    survives a future repeat purge of the same engagement).
    try:
        log = AuditLog(str(audit_log_path() if not audit_path else audit_path))
        await log.write(AuditEntry(
            engagement_id="-", actor=actor, action="gdpr_purge",
            details={
                "purged_engagement_id": engagement_id,
                "reason": reason,
                "stats": {
                    "findings": result.deleted_findings,
                    "credentials": result.deleted_credentials,
                    "hosts": result.deleted_hosts,
                    "engagement": result.deleted_engagement,
                    "audit_lines": result.deleted_audit_lines,
                    "reports": result.deleted_report_files,
                    "tool_output_rows": result.deleted_tool_output_rows,
                    "tool_output_dirs": result.deleted_tool_output_dirs,
                },
            },
        ))
        await log.flush()
        await log.close()
    except Exception as exc:
        result.errors.append(f"audit_record: {exc}")

    return result


def _audit_purge_engagement(audit_file: Path, engagement_id: str) -> int:
    """Remove matching JSONL lines and rebuild the hash chain in place."""
    removed = 0
    new_lines: list[str] = []
    prev_hash = ""
    with open(audit_file, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # Preserve unparseable lines (better safe than lossy).
                new_lines.append(raw if raw.endswith("\n") else raw + "\n")
                continue
            if obj.get("engagement_id") == engagement_id:
                removed += 1
                continue
            obj.pop("_prev", None)
            obj.pop("_hash", None)
            obj["_prev"] = prev_hash
            canon = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            h = hashlib.blake2b(canon, digest_size=32).hexdigest()
            obj["_hash"] = h
            new_lines.append(json.dumps(obj, separators=(",", ":")) + "\n")
            prev_hash = h

    if removed == 0:
        return 0

    tmp = audit_file.with_suffix(audit_file.suffix + ".purge.tmp")
    tmp.write_text("".join(new_lines), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, audit_file)
    # Refresh sidecar head.
    head_path = audit_file.with_suffix(audit_file.suffix + ".head")
    try:
        head_path.write_text(prev_hash, encoding="utf-8")
        os.chmod(head_path, 0o600)
    except OSError:
        pass
    return removed


# ──────────────────────────────────────────────────────────────────────────
# Retention policy
# ──────────────────────────────────────────────────────────────────────────

async def apply_retention(
    *,
    audit_max_age_days: int = 180,
    tool_output_max_age_days: int = 180,
    audit_path: Optional[str] = None,
    actor: str = "system",
) -> RetentionResult:
    """Drop audit lines and tool outputs older than the retention windows."""
    res = RetentionResult()
    now = time.time()

    # Audit log: rewrite the chain keeping only entries newer than cutoff.
    try:
        ap = Path(audit_path) if audit_path else audit_log_path()
        if ap.exists() and audit_max_age_days > 0:
            cutoff = now - audit_max_age_days * 86400
            removed = _audit_purge_older_than(ap, cutoff)
            res.audit_lines_removed = removed
            res.audit_chain_rewritten = removed > 0
    except Exception:
        pass

    # Tool output store retention.
    try:
        from core.tool_output_store import get_tool_output_store
        tos = get_tool_output_store()
        stats = await tos.gc(retention_days=tool_output_max_age_days, dry_run=False)
        res.tool_output_rows_removed = stats.get("deleted_rows", 0)
        res.tool_output_dirs_removed = stats.get("deleted_dirs", 0)
    except Exception:
        pass

    # Audit the retention sweep itself.
    try:
        log = AuditLog(str(audit_log_path() if not audit_path else audit_path))
        await log.write(AuditEntry(
            engagement_id="-", actor=actor, action="gdpr_retention",
            details={
                "audit_max_age_days": audit_max_age_days,
                "tool_output_max_age_days": tool_output_max_age_days,
                "audit_lines_removed": res.audit_lines_removed,
                "tool_output_rows_removed": res.tool_output_rows_removed,
                "tool_output_dirs_removed": res.tool_output_dirs_removed,
            },
        ))
        await log.flush()
        await log.close()
    except Exception:
        pass
    return res


def _audit_purge_older_than(audit_file: Path, cutoff_epoch: float) -> int:
    """Drop entries with ``timestamp`` older than ``cutoff_epoch`` (UTC ts)."""
    from datetime import datetime, timezone

    removed = 0
    new_lines: list[str] = []
    prev_hash = ""
    with open(audit_file, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                new_lines.append(raw if raw.endswith("\n") else raw + "\n")
                continue
            ts_raw = obj.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                ts_epoch = ts.timestamp()
            except Exception:
                ts_epoch = cutoff_epoch  # cannot parse → keep
            if ts_epoch < cutoff_epoch:
                removed += 1
                continue
            obj.pop("_prev", None)
            obj.pop("_hash", None)
            obj["_prev"] = prev_hash
            canon = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            h = hashlib.blake2b(canon, digest_size=32).hexdigest()
            obj["_hash"] = h
            new_lines.append(json.dumps(obj, separators=(",", ":")) + "\n")
            prev_hash = h

    if removed == 0:
        return 0
    tmp = audit_file.with_suffix(audit_file.suffix + ".retention.tmp")
    tmp.write_text("".join(new_lines), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, audit_file)
    head_path = audit_file.with_suffix(audit_file.suffix + ".head")
    try:
        head_path.write_text(prev_hash, encoding="utf-8")
        os.chmod(head_path, 0o600)
    except OSError:
        pass
    return removed
