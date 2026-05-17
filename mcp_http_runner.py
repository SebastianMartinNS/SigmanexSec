#!/usr/bin/env python3
"""
Wrapper to run one of the pentest MCP servers over HTTP for the llama.cpp WebUI
and for the dashboard's MCP transport.

Usage::

    python3 mcp_http_runner.py <server_name> <port>
    # server_name in: engagement | recon | exploit | blueteam | parrot | osint

Or via the installed console script::

    sap-mcp-runner <server_name> <port>

Two probe endpoints are exposed for every MCP server:

* ``GET /healthz`` — cheap liveness, always 200 once the process is up.
* ``GET /readyz``  — deep readiness, asserts the MCP transport is ready.

Both bypass the MCP framing so a Kubernetes / systemd probe can hit them
every few seconds without polluting MCP session state.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


_STARTED_AT = time.monotonic()
_HEALTH_PATHS = {"/healthz", "/readyz"}


def _wrap_session_404(app):
    """Translate MCP-SDK 400 "session ID" errors into HTTP 404.

    The MCP Python SDK returns HTTP 400 ("Bad Request: No valid session ID
    provided" / "transport with session ID ... not found") when a client
    sends a stale ``Mcp-Session-Id`` (e.g. after a server restart). The
    llama.cpp WebUI — per MCP spec 2025-11-25 — only treats HTTP 404 as
    "session expired, drop the id and reinitialize". With 400 it loops
    forever and the chat UI hangs on "processing". We rewrite those
    specific 400s to 404 so the WebUI auto-heals.
    """

    async def wrapped(scope, receive, send):
        if scope.get("type") != "http":
            await app(scope, receive, send)
            return

        state = {"intercept": False, "started": False, "start": None}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if message.get("status") == 400:
                    state["intercept"] = True
                    state["start"] = message
                    return
                state["started"] = True
                await send(message)
                return

            if state["intercept"]:
                if message["type"] == "http.response.body":
                    body = message.get("body", b"") or b""
                    text = body.decode("utf-8", errors="replace")
                    if "session ID" in text or "transport with session ID" in text:
                        rewritten = dict(state["start"])
                        rewritten["status"] = 404
                        await send(rewritten)
                        await send(message)
                        state["started"] = True
                        state["intercept"] = False
                        return
                # Not the targeted 400 — flush the buffered start untouched.
                await send(state["start"])
                state["started"] = True
                state["intercept"] = False
                await send(message)
                return

            await send(message)

        await app(scope, receive, send_wrapper)

    return wrapped


def _wrap_health(app, server_name: str):
    """Short-circuit /healthz and /readyz so probes never enter the MCP framing."""

    async def wrapped(scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") not in _HEALTH_PATHS:
            await app(scope, receive, send)
            return

        path = scope["path"]
        if path == "/healthz":
            payload = {
                "status": "ok",
                "server": server_name,
                "uptime_seconds": round(time.monotonic() - _STARTED_AT, 2),
            }
            status_code = 200
        else:
            # /readyz: confirm the MCP module's singletons (audit log dir,
            # session db) are at minimum reachable. Cheap, non-blocking.
            ready, checks = _readyz_checks()
            payload = {"ready": ready, "server": server_name, "checks": checks}
            status_code = 200 if ready else 503

        body = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    return wrapped


def _readyz_checks() -> tuple[bool, dict]:
    """Lightweight readiness assertions for the MCP server process."""
    checks: dict[str, dict] = {}
    ready = True

    audit_path = Path(os.environ.get("AUDIT_LOG_PATH", "./logs/audit.jsonl"))
    audit_dir = audit_path.parent
    audit_ok = audit_dir.exists() and os.access(audit_dir, os.W_OK)
    checks["audit_log_dir"] = {"ok": audit_ok, "path": str(audit_dir)}
    ready = ready and audit_ok

    session_db = Path(os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db"))
    sess_ok = session_db.exists()
    checks["session_db"] = {"ok": sess_ok, "path": str(session_db)}
    ready = ready and sess_ok

    return ready, checks


async def _serve(mcp, server_name: str) -> None:
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware

    starlette_app = mcp.streamable_http_app()
    # Permissive CORS so the WebUI can talk DIRECTLY to the MCP servers
    # (different ports = different origins) instead of going through
    # llama-server's /cors-proxy. This avoids exhausting the browser's 6
    # connections-per-origin limit on 127.0.0.1:8080 with long-lived SSE
    # streams, which was queueing the /v1/chat/completions POST forever.
    starlette_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"],
    )
    wrapped_app = _wrap_health(_wrap_session_404(starlette_app), server_name)

    config = uvicorn.Config(
        wrapped_app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    await server.serve()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    name, port_str = args
    try:
        port = int(port_str)
    except ValueError:
        print(f"invalid port: {port_str}", file=sys.stderr)
        return 2

    # FastMCP reads host/port from pydantic Settings (env prefix FASTMCP_).
    os.environ.setdefault("FASTMCP_HOST", "127.0.0.1")
    os.environ["FASTMCP_PORT"] = str(port)

    try:
        mod = importlib.import_module(f"mcp_servers.{name}_server")
    except ImportError as exc:
        print(f"unknown MCP server '{name}': {exc}", file=sys.stderr)
        return 2

    mcp = mod.mcp
    mcp.settings.host = os.environ["FASTMCP_HOST"]
    mcp.settings.port = port

    # Force JSON-response mode on the streamable-HTTP transport. The default
    # SSE mode races with the WebUI's reconnect cycle (POST /mcp is accepted
    # but the response arrives on the GET /mcp SSE stream the client may
    # not have re-opened yet) → tools/list hangs for 60s and times out with
    # ``MCP error -32001``. JSON-mode delivers the full JSON-RPC reply on
    # the POST response itself, eliminating the race.
    mcp.settings.json_response = True

    print(
        f"[mcp:{name}] http://{mcp.settings.host}:{port}{mcp.settings.streamable_http_path}"
        f"  (stale-session 400→404 patch active, /healthz + /readyz exposed)",
        flush=True,
    )
    asyncio.run(_serve(mcp, name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
