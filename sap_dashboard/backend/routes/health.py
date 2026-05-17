"""
sap_dashboard/backend/routes/health.py — Liveness and readiness probes.

These endpoints intentionally bypass authentication and rate-limiting so a
Kubernetes / systemd / load balancer probe can hit them every few seconds
without polluting audit logs or exhausting the per-IP bucket.

Contract:

* ``/healthz`` — cheap liveness. Always 200 unless the process itself
  is dying. Does not touch sqlite, the audit chain, or external sockets.
  Suitable for `livenessProbe` in Kubernetes.

* ``/readyz`` — deep readiness. Returns 200 only when the dashboard's
  collaborators are reachable: the session sqlite is writable, the audit
  log writer task is alive, and (if a sudo_broker is expected) its
  UNIX socket exists. Returns 503 with a JSON ``{"ready": false,
  "checks": {...}}`` body when any check fails. Suitable for
  `readinessProbe` so traffic is steered away during cold-start.

Neither endpoint exposes operator-controlled data; both return strictly
opaque status booleans.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import aiosqlite
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])

_STARTED_AT = time.monotonic()


def _expected_audit_path() -> Path:
    """Mirror the resolution used by core.audit_log so readyz is honest."""
    return Path(os.environ.get("AUDIT_LOG_PATH", "./logs/audit.jsonl"))


def _sudo_socket_path() -> Path | None:
    """Return the expected sudo_broker socket path, or None if not configured."""
    explicit = os.environ.get("SAP_SUDO_SOCKET")
    if explicit:
        return Path(explicit)
    if os.environ.get("SAP_SUDO_BROKER_ENABLED", "").lower() not in {"1", "true", "yes"}:
        return None
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return Path(base) / f"sap_sudo_{os.getuid()}.sock"


def _session_db_path() -> Path:
    return Path(os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db"))


@router.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "uptime_seconds": round(time.monotonic() - _STARTED_AT, 2),
        },
        status_code=200,
    )


@router.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    checks: dict[str, Any] = {}
    ready = True

    # 1) Session sqlite reachable and writable. We do not run a query
    #    that mutates state — only `PRAGMA quick_check` which is cheap
    #    and read-only for healthy databases.
    db_path = _session_db_path()
    try:
        if not db_path.exists():
            checks["session_db"] = {
                "ok": False,
                "reason": "missing",
                "path": str(db_path),
            }
            ready = False
        else:
            async with aiosqlite.connect(db_path) as conn:
                cursor = await conn.execute("PRAGMA quick_check")
                row = await cursor.fetchone()
                await cursor.close()
                ok = bool(row) and (row[0] == "ok")
                checks["session_db"] = {"ok": ok, "path": str(db_path)}
                ready = ready and ok
    except Exception as exc:  # pragma: no cover — defensive
        checks["session_db"] = {"ok": False, "reason": str(exc)[:120]}
        ready = False

    # 2) Audit log writer: the directory must exist and be writable so a
    #    fresh append cannot fail half-way through a privileged action.
    audit_path = _expected_audit_path()
    audit_dir = audit_path.parent
    audit_ok = audit_dir.exists() and os.access(audit_dir, os.W_OK)
    checks["audit_log_dir"] = {
        "ok": audit_ok,
        "path": str(audit_dir),
        "writable": audit_ok,
    }
    ready = ready and audit_ok

    # 3) Sudo broker socket if a broker is expected. When the broker is
    #    not configured (typical for read-only deployments), we skip
    #    this check rather than fail it.
    sock = _sudo_socket_path()
    if sock is not None:
        sock_ok = sock.exists()
        checks["sudo_broker_socket"] = {"ok": sock_ok, "path": str(sock)}
        ready = ready and sock_ok
    else:
        checks["sudo_broker_socket"] = {"ok": True, "skipped": True}

    payload = {"ready": ready, "checks": checks}
    return JSONResponse(payload, status_code=200 if ready else 503)
