"""Tests for the /healthz and /readyz ASGI wrappers added to mcp_http_runner."""

from __future__ import annotations

import json

import pytest

import mcp_http_runner as runner


class _AsgiInvocation:
    """Minimal ASGI driver: feed a scope and collect response messages."""

    def __init__(self, app, path: str = "/", method: str = "GET") -> None:
        self.app = app
        self.scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": [],
            "query_string": b"",
        }
        self.messages: list[dict] = []

    async def run(self) -> None:
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            self.messages.append(message)

        await self.app(self.scope, receive, send)

    @property
    def status(self) -> int:
        for m in self.messages:
            if m["type"] == "http.response.start":
                return int(m["status"])
        raise AssertionError("no response.start in messages")

    @property
    def body_bytes(self) -> bytes:
        out = b""
        for m in self.messages:
            if m["type"] == "http.response.body":
                out += m.get("body", b"") or b""
        return out

    @property
    def json(self) -> dict:
        return json.loads(self.body_bytes.decode("utf-8"))


async def _inner_app(scope, receive, send):
    """Stand-in for the wrapped MCP starlette app. Should never be called
    when the request is /healthz or /readyz."""
    body = b"INNER"
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


@pytest.mark.asyncio
async def test_healthz_short_circuits_inner_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "logs" / "audit.jsonl"))
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "s.db"))
    (tmp_path / "s.db").write_bytes(b"")

    wrapped = runner._wrap_health(_inner_app, "recon")
    inv = _AsgiInvocation(wrapped, path="/healthz")
    await inv.run()

    assert inv.status == 200
    body = inv.json
    assert body["status"] == "ok"
    assert body["server"] == "recon"
    assert body["uptime_seconds"] >= 0
    # Inner app body must NOT leak through.
    assert b"INNER" not in inv.body_bytes


@pytest.mark.asyncio
async def test_readyz_ok_when_paths_exist(tmp_path, monkeypatch):
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.setenv("AUDIT_LOG_PATH", str(logs / "audit.jsonl"))
    sess = tmp_path / "sessions.db"
    sess.write_bytes(b"")
    monkeypatch.setenv("SESSION_DB_PATH", str(sess))

    wrapped = runner._wrap_health(_inner_app, "engagement")
    inv = _AsgiInvocation(wrapped, path="/readyz")
    await inv.run()

    assert inv.status == 200
    body = inv.json
    assert body["ready"] is True
    assert body["checks"]["audit_log_dir"]["ok"] is True
    assert body["checks"]["session_db"]["ok"] is True


@pytest.mark.asyncio
async def test_readyz_fails_when_audit_dir_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "missing" / "audit.jsonl"))
    sess = tmp_path / "sessions.db"
    sess.write_bytes(b"")
    monkeypatch.setenv("SESSION_DB_PATH", str(sess))

    wrapped = runner._wrap_health(_inner_app, "exploit")
    inv = _AsgiInvocation(wrapped, path="/readyz")
    await inv.run()

    assert inv.status == 503
    body = inv.json
    assert body["ready"] is False
    assert body["checks"]["audit_log_dir"]["ok"] is False


@pytest.mark.asyncio
async def test_non_health_path_passes_through_to_inner_app(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "s.db"))

    wrapped = runner._wrap_health(_inner_app, "osint")
    inv = _AsgiInvocation(wrapped, path="/mcp")
    await inv.run()

    assert inv.status == 200
    assert b"INNER" in inv.body_bytes


def test_main_rejects_missing_arguments(capsys):
    rc = runner.main([])
    assert rc == 2

    rc = runner.main(["only_one"])
    assert rc == 2


def test_main_rejects_invalid_port(capsys):
    rc = runner.main(["recon", "not-a-port"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "invalid port" in err


def test_main_rejects_unknown_server(capsys):
    rc = runner.main(["does_not_exist", "9000"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown MCP server" in err
