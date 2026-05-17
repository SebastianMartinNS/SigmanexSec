"""Tests for core/logging.py — structlog setup and correlation-id propagation."""

from __future__ import annotations

import json
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import core.logging as sap_logging


@pytest.fixture(autouse=True)
def _reset_logging_state(monkeypatch):
    """Reset module-level state so each test sees a clean slate."""
    monkeypatch.setattr(sap_logging, "_configured", False)
    # Clear any correlation id leaked from a previous test in this module.
    sap_logging.correlation_id_var.set(None)
    yield
    monkeypatch.setattr(sap_logging, "_configured", False)
    sap_logging.correlation_id_var.set(None)


def test_configure_logging_is_idempotent(monkeypatch):
    """Calling configure_logging multiple times must not double-bridge stdlib."""
    sap_logging.configure_logging(level=logging.INFO, json_output=True)
    assert sap_logging._configured is True
    # Second call should no-op (no exception, _configured stays True).
    sap_logging.configure_logging(level=logging.DEBUG, json_output=False)
    assert sap_logging._configured is True


def test_get_logger_returns_bound_logger():
    log = sap_logging.get_logger("test")
    # structlog BoundLogger exposes the bind / info / warning surface.
    assert hasattr(log, "info")
    assert hasattr(log, "bind")


def test_json_mode_emits_parseable_json(monkeypatch, capsys):
    """JSON output must be one JSON object per line, with expected keys."""
    monkeypatch.setenv("SAP_LOG_FORMAT", "json")
    sap_logging.configure_logging(level=logging.INFO, json_output=True)
    log = sap_logging.get_logger("json_emit")
    log.info("test.event", key="value", count=42)

    captured = capsys.readouterr().err.strip().splitlines()
    assert captured, "expected at least one JSON log line"
    record = json.loads(captured[-1])
    assert record["event"] == "test.event"
    assert record["key"] == "value"
    assert record["count"] == 42
    assert record["level"] == "info"
    assert "timestamp" in record


def test_correlation_id_contextvar_roundtrip():
    assert sap_logging.current_correlation_id() is None
    cid = sap_logging.new_correlation_id()
    assert len(cid) == 32  # uuid4 hex
    sap_logging.bind_correlation_id(cid)
    assert sap_logging.current_correlation_id() == cid


def test_new_correlation_id_is_unique():
    ids = {sap_logging.new_correlation_id() for _ in range(100)}
    assert len(ids) == 100


def test_correlation_id_middleware_generates_and_echoes(monkeypatch):
    """The middleware must echo back the cid and bind it during the request."""
    app = FastAPI()
    app.add_middleware(sap_logging.CorrelationIdMiddleware)
    captured: dict[str, str | None] = {}

    @app.get("/probe")
    def probe():
        captured["bound"] = sap_logging.current_correlation_id()
        return {"ok": True}

    client = TestClient(app)
    response = client.get("/probe")
    assert response.status_code == 200
    echoed = response.headers.get(sap_logging.CORRELATION_HEADER)
    assert echoed is not None and len(echoed) == 32
    assert captured["bound"] == echoed
    # After the request, the contextvar must be cleared (reset by middleware).
    assert sap_logging.current_correlation_id() is None


def test_correlation_id_middleware_preserves_incoming_header():
    """If the caller supplies a cid we trust it (for distributed tracing)."""
    app = FastAPI()
    app.add_middleware(sap_logging.CorrelationIdMiddleware)

    @app.get("/echo")
    def echo():
        return {"cid": sap_logging.current_correlation_id()}

    client = TestClient(app)
    incoming = "deadbeef" * 4
    response = client.get(
        "/echo", headers={sap_logging.CORRELATION_HEADER: incoming}
    )
    assert response.status_code == 200
    assert response.headers[sap_logging.CORRELATION_HEADER] == incoming
    assert response.json() == {"cid": incoming}


def test_correlation_id_appears_in_log_record(monkeypatch, capsys):
    """When a cid is bound, every structlog record emitted in that context
    must carry the correlation_id field."""
    monkeypatch.setenv("SAP_LOG_FORMAT", "json")
    sap_logging.configure_logging(level=logging.INFO, json_output=True)

    cid = "abc" * 10 + "ab"  # 32 chars
    sap_logging.bind_correlation_id(cid)
    log = sap_logging.get_logger("cid_emit")
    log.info("with.cid")

    out = capsys.readouterr().err.strip().splitlines()[-1]
    record = json.loads(out)
    assert record["correlation_id"] == cid


def test_console_format_does_not_break_when_no_tty(monkeypatch, capsys):
    """Forcing console mode must produce non-JSON, human-readable output."""
    monkeypatch.setenv("SAP_LOG_FORMAT", "console")
    sap_logging.configure_logging(level=logging.INFO, json_output=False)
    log = sap_logging.get_logger("console_emit")
    log.info("plain.event", foo="bar")

    out = capsys.readouterr().err
    # Console renderer puts the event name in the output, but not as a JSON key.
    assert "plain.event" in out
    # Must NOT be valid JSON (it is human-readable).
    with pytest.raises(json.JSONDecodeError):
        json.loads(out.strip().splitlines()[-1])
