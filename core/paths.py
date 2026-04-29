"""
core/paths.py — Centralized path & environment helpers.

All filesystem locations used by the platform are resolved here,
so they can be overridden consistently via environment variables
and pre-created idempotently.
"""
from __future__ import annotations

import os
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _env_path(var: str, default: Path) -> Path:
    raw = os.environ.get(var)
    return Path(raw).expanduser() if raw else default


def sessions_dir() -> Path:
    p = _env_path("SAP_SESSIONS_DIR", REPO_ROOT / "sessions")
    p.mkdir(parents=True, exist_ok=True)
    return p


def logs_dir() -> Path:
    p = _env_path("SAP_LOGS_DIR", REPO_ROOT / "logs")
    p.mkdir(parents=True, exist_ok=True)
    return p


def reports_dir() -> Path:
    p = _env_path("SAP_REPORTS_DIR", REPO_ROOT / "reports")
    p.mkdir(parents=True, exist_ok=True)
    return p


def assessments_db_path() -> Path:
    return _env_path("SESSION_DB_PATH", sessions_dir() / "assessments.db")


def memory_db_path() -> Path:
    return _env_path("SAP_MEMORY_DB_PATH", sessions_dir() / "memory.db")


def audit_log_path() -> Path:
    return _env_path("AUDIT_LOG_PATH", logs_dir() / "audit.jsonl")


def keysalt_path() -> Path:
    return _env_path("SAP_KEYSALT_PATH", sessions_dir() / ".keysalt")


def is_dev_mode() -> bool:
    """True when the platform may run with insecure default secrets.

    Enabled when SAP_DEV_MODE is set to a truthy value.
    """
    return os.environ.get("SAP_DEV_MODE", "").lower() in ("1", "true", "yes", "on")
