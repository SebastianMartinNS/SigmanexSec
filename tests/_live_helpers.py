"""Helpers for live OSINT tests.

These tests actually invoke real binaries against real network targets, so
they are gated behind ``@pytest.mark.live`` AND ``SAP_LIVE_OSINT=1`` env.
The default ``pytest tests/`` run skips them entirely (see pyproject.toml
``addopts = -m 'not live and not lab'``).

Each helper raises ``pytest.skip`` (not ``pytest.fail``) so a missing
binary or a network outage produces a CLEAR skip, not a false failure.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket

import pytest

from core.models import Engagement, EngagementCreate
from core.session_store import SessionStore


def require_live() -> None:
    """Skip unless ``SAP_LIVE_OSINT=1`` is set in the env."""
    if os.environ.get("SAP_LIVE_OSINT") != "1":
        pytest.skip("live OSINT tests disabled (set SAP_LIVE_OSINT=1 to enable)")


def require_binary(name: str) -> None:
    """Skip if the named binary is not on PATH."""
    if shutil.which(name) is None:
        pytest.skip(f"binary '{name}' not installed (skipping live test)")


def require_network(host: str = "github.com", port: int = 443, timeout: float = 3.0) -> None:
    """Skip if the host:port is unreachable in ``timeout`` seconds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        pytest.skip(f"network unreachable ({host}:{port} → {exc!r})")


async def make_osint_engagement(
    *,
    scope_emails: list[str] | None = None,
    scope_usernames: list[str] | None = None,
    scope_persons: list[str] | None = None,
    scope_social_handles: list[str] | None = None,
    scope_domains: list[str] | None = None,
) -> Engagement:
    """Create and persist an OSINT-authorized engagement for live tests.

    The engagement is written into the SAME ``SessionStore`` instance that
    ``mcp_servers.osint_server`` will query — otherwise an env-redirected
    test DB would be invisible to the module-level singleton bound at
    import time.
    """
    create = EngagementCreate(
        name="LIVE-OSINT",
        client="self-test",
        tester="qa",
        authorization_ref="LIVE-INFRA-AUTH",
        osint_authorization_ref="LIVE-OSINT-AUTH",
        scope_emails=scope_emails or [],
        scope_usernames=scope_usernames or [],
        scope_persons=scope_persons or [],
        scope_social_handles=scope_social_handles or [],
        scope_domains=scope_domains or [],
    )
    eng = Engagement(**create.model_dump())
    # Use the server's own store so the engagement is visible to its tools.
    from mcp_servers import osint_server as _osint
    await _osint.store.init()
    await _osint.store.create_engagement(eng)
    return eng


def run_async(coro):
    """Wrapper to run an async test body inside a sync pytest test."""
    return asyncio.run(coro)
