"""Shared pytest fixtures."""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Force the embedding fallback path so tests don't need ~120 MB of weights.
os.environ.setdefault("SAP_DISABLE_ST", "1")
# Allow the dev encryption fallback for tests so we don't have to manage keys.
os.environ.setdefault("SAP_DEV_MODE", "1")


@pytest.fixture()
def tmp_paths(tmp_path, monkeypatch):
    """Redirect every persistence path into a per-test temp dir."""
    sessions = tmp_path / "sessions"
    logs = tmp_path / "logs"
    reports = tmp_path / "reports"
    for p in (sessions, logs, reports):
        p.mkdir()
    monkeypatch.setenv("SAP_SESSIONS_DIR", str(sessions))
    monkeypatch.setenv("SAP_LOGS_DIR", str(logs))
    monkeypatch.setenv("SAP_REPORTS_DIR", str(reports))
    monkeypatch.setenv("SESSION_DB_PATH", str(sessions / "assessments.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(logs / "audit.jsonl"))
    monkeypatch.setenv("SAP_MEMORY_DB_PATH", str(sessions / "memory.db"))
    monkeypatch.setenv("SAP_KEYSALT_PATH", str(sessions / ".keysalt"))
    # Force key cache reset for tests
    from core import session_store

    session_store._KEY_CACHE = None

    # Rebind module-level store/audit/exe singletons that MCP servers
    # capture at import time so every test sees the per-test tmp paths.
    # Without this, the first test that imports any of these modules
    # "wins" the binding for the whole session and later tests look in
    # a deleted tmp dir.
    from core.audit_log import AuditLog
    from core.executor import ToolExecutor
    from core.session_store import SessionStore

    _new_store = SessionStore(os.environ["SESSION_DB_PATH"])
    _new_audit = AuditLog(os.environ["AUDIT_LOG_PATH"])

    for _modname in ("mcp_servers.osint_server",
                     "mcp_servers.parrot_server",
                     "mcp_servers.blueteam_server"):
        try:
            _mod = __import__(_modname, fromlist=["*"])
        except Exception:
            continue
        if hasattr(_mod, "store"):
            monkeypatch.setattr(_mod, "store", _new_store, raising=False)
        if hasattr(_mod, "audit"):
            monkeypatch.setattr(_mod, "audit", _new_audit, raising=False)
        if hasattr(_mod, "_exe"):
            monkeypatch.setattr(
                _mod, "_exe", ToolExecutor(audit_log=_new_audit), raising=False
            )

    yield {
        "sessions": sessions,
        "logs": logs,
        "reports": reports,
    }


# ── v3.1 T2: environment-dependency markers ────────────────────────────────
#
# Hook called by pytest for every collected item; skips the item with a
# clear reason when the marker's argument is not available. Centralised
# here so test files only have to say::
#
#     @pytest.mark.requires_dep("structlog")
#     def test_…(): ...
#
# instead of repeating ``importlib.util.find_spec`` shims everywhere.


def _has_dep(name: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(name) is not None


def _has_binary(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


def pytest_runtest_setup(item):
    """Auto-skip when ``requires_dep`` / ``requires_binary`` / ``requires_network``
    markers reference something that is not available in the current env."""
    for marker in item.iter_markers(name="requires_dep"):
        if not marker.args:
            continue
        dep = marker.args[0]
        if not _has_dep(dep):
            pytest.skip(f"requires Python package not installed: {dep!r}")
    for marker in item.iter_markers(name="requires_binary"):
        if not marker.args:
            continue
        binary = marker.args[0]
        if not _has_binary(binary):
            pytest.skip(f"requires CLI binary on PATH: {binary!r}")
    for _marker in item.iter_markers(name="requires_network"):
        if os.environ.get("SAP_TEST_OFFLINE", "0") not in ("", "0", "false", "False"):
            pytest.skip("requires network (SAP_TEST_OFFLINE=1)")


@pytest.fixture()
def engagement_id() -> str:
    return f"eng_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def lab_cidr() -> str:
    cidr = os.environ.get("PENTEST_LAB_CIDR", "")
    if not cidr:
        pytest.skip("PENTEST_LAB_CIDR not set; skipping lab test")
    return cidr


@pytest.fixture()
def live_engagement(tmp_paths):
    """Persisted engagement with the canonical canary identity scope.

    Audit log + sessions DB are redirected into ``tmp_paths`` (per-test
    temp dir): we rebind ``mcp_servers.osint_server.store`` and ``audit``
    to fresh instances pointing at the temp paths so live tests do NOT
    pollute the real ``logs/audit.jsonl`` or ``sessions/assessments.db``.
    """
    import asyncio as _asyncio

    from core.audit_log import AuditLog
    from core.executor import ToolExecutor
    from core.session_store import SessionStore
    from mcp_servers import osint_server as _osint
    from tests._live_helpers import make_osint_engagement

    # Rebind the singletons that osint_server captured at import time.
    _osint.store = SessionStore(os.environ["SESSION_DB_PATH"])
    _osint.audit = AuditLog(os.environ["AUDIT_LOG_PATH"])
    _osint._exe = ToolExecutor(audit_log=_osint.audit)

    return _asyncio.run(make_osint_engagement(
        scope_usernames=["octocat"],
        scope_emails=["octocat@github.com"],
        scope_persons=["octocat"],
        scope_social_handles=["octocat"],
        scope_domains=["example.com"],
    ))
