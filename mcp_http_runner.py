#!/usr/bin/env python3
"""
Wrapper to run one of the pentest MCP servers over HTTP for the llama.cpp WebUI.

Usage:
    python3 mcp_http_runner.py <server_name> <port>
    # server_name in: engagement | recon | exploit | blueteam | parrot | osint
"""
import asyncio
import importlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

if len(sys.argv) != 3:
    print(__doc__, file=sys.stderr)
    sys.exit(2)

name, port = sys.argv[1], int(sys.argv[2])

# FastMCP reads host/port from pydantic Settings (env prefix FASTMCP_).
os.environ.setdefault("FASTMCP_HOST", "127.0.0.1")
os.environ["FASTMCP_PORT"] = str(port)

mod = importlib.import_module(f"mcp_servers.{name}_server")
mcp = mod.mcp
mcp.settings.host = os.environ["FASTMCP_HOST"]
mcp.settings.port = port

# Force JSON-response mode on the streamable-HTTP transport. The default SSE
# response mode has a race with the WebUI's reconnect cycle (POST /mcp is
# accepted but the response is delivered on the GET /mcp SSE stream which the
# client may not have re-opened yet) → tools/list hangs for 60s and times out
# with `MCP error -32001`. JSON-mode delivers the full JSON-RPC reply on the
# POST response itself, eliminating the race.
mcp.settings.json_response = True


# ── Middleware: 400 "session ID" → 404 ───────────────────────────────────────
# The MCP Python SDK returns HTTP 400 ("Bad Request: No valid session ID
# provided" / "transport with session ID ... not found") when a client sends a
# stale Mcp-Session-Id (e.g. after a server restart). The llama.cpp WebUI —
# per MCP spec 2025-11-25 — only treats HTTP 404 as "session expired, drop the
# id and reinitialize". With 400 it loops forever and the chat UI hangs on
# "processing". We rewrite those specific 400s to 404 so the WebUI auto-heals.
def _wrap_session_404(app):
    async def wrapped(scope, receive, send):
        if scope.get("type") != "http":
            await app(scope, receive, send)
            return

        state = {"intercept": False, "started": False}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                if message.get("status") == 400:
                    # Buffer the start frame; decide based on body content.
                    state["intercept"] = True
                    state["start"] = message
                    return
                state["started"] = True
                await send(message)
                return

            if message["type"] == "http.response.body" and state["intercept"]:
                body = message.get("body", b"") or b""
                text = body.decode("utf-8", errors="replace").lower()
                if (
                    "session id" in text
                    or "transport with session" in text
                    or "mcp-session-id" in text
                ):
                    start = state["start"]
                    new_headers = []
                    for k, v in start.get("headers") or []:
                        if k.lower() == b"content-length":
                            continue
                        new_headers.append((k, v))
                    new_body = b"Not Found: Session expired or invalid"
                    new_headers.append(
                        (b"content-length", str(len(new_body)).encode())
                    )
                    await send({
                        "type": "http.response.start",
                        "status": 404,
                        "headers": new_headers,
                    })
                    await send({
                        "type": "http.response.body",
                        "body": new_body,
                        "more_body": False,
                    })
                    state["intercept"] = False
                    state["started"] = True
                    return
                # Not the session error — flush original 400 unchanged.
                await send(state["start"])
                state["started"] = True
                state["intercept"] = False
                await send(message)
                return

            await send(message)

        await app(scope, receive, send_wrapper)

    return wrapped


async def _serve():
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
    wrapped_app = _wrap_session_404(starlette_app)

    config = uvicorn.Config(
        wrapped_app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    await server.serve()


print(
    f"[mcp:{name}] http://{mcp.settings.host}:{port}{mcp.settings.streamable_http_path}"
    f"  (stale-session 400→404 patch active)",
    flush=True,
)
asyncio.run(_serve())
