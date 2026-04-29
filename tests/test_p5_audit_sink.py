"""P5 — external audit sinks + governance docs."""
from __future__ import annotations

import json
import os
import socket
import threading
from pathlib import Path

import pytest

from core.audit_sink import (
    BaseSink,
    FileSink,
    SyslogConfig,
    SyslogSink,
    build_sinks_from_env,
)


# ── FileSink ────────────────────────────────────────────────────────────────

def test_file_sink_appends_lines(tmp_path):
    p = tmp_path / "mirror.jsonl"
    s = FileSink(p)
    s.emit('{"a":1}')
    s.emit('{"a":2}\n')
    out = p.read_text(encoding="utf-8").splitlines()
    assert out == ['{"a":1}', '{"a":2}']


def test_file_sink_creates_parent(tmp_path):
    p = tmp_path / "deep" / "nested" / "audit.log"
    FileSink(p).emit("hello")
    assert p.read_text(encoding="utf-8") == "hello\n"


def test_file_sink_swallows_oserror(tmp_path, monkeypatch):
    p = tmp_path / "mirror.jsonl"
    s = FileSink(p)
    def boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr("builtins.open", boom)
    s.emit("ignored")  # must not raise


# ── SyslogSink (UDP, real socket) ───────────────────────────────────────────

def test_syslog_sink_udp_roundtrip():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2.0)
    host, port = server.getsockname()

    sink = SyslogSink(SyslogConfig(host=host, port=port, transport="udp"))
    sink.emit('{"event":"login","user":"alice"}')

    data, _ = server.recvfrom(4096)
    server.close()
    sink.close()

    text = data.decode("utf-8")
    # PRI = facility*8 + severity = 13*8 + 5 = 109.
    assert text.startswith("<109>1 ")
    assert "sap-audit" in text
    assert '"event":"login"' in text


def test_syslog_sink_emit_drops_on_unreachable_host():
    # Connect to a closed port; emit must not raise.
    sink = SyslogSink(SyslogConfig(host="127.0.0.1", port=1, transport="tcp", timeout_s=0.2))
    sink.emit("anything")  # must not raise
    sink.close()


# ── Factory ─────────────────────────────────────────────────────────────────

def test_build_sinks_from_env_empty(monkeypatch):
    for k in (
        "SAP_AUDIT_SINK_FILE",
        "SAP_AUDIT_SINK_SYSLOG",
        "SAP_AUDIT_SINK_SYSLOG_TRANSPORT",
        "SAP_AUDIT_SINK_SYSLOG_CA",
    ):
        monkeypatch.delenv(k, raising=False)
    assert build_sinks_from_env() == []


def test_build_sinks_from_env_file(tmp_path, monkeypatch):
    p = tmp_path / "audit.mirror"
    monkeypatch.setenv("SAP_AUDIT_SINK_FILE", str(p))
    monkeypatch.delenv("SAP_AUDIT_SINK_SYSLOG", raising=False)
    sinks = build_sinks_from_env()
    assert len(sinks) == 1 and isinstance(sinks[0], FileSink)


def test_build_sinks_from_env_syslog_udp(monkeypatch):
    monkeypatch.delenv("SAP_AUDIT_SINK_FILE", raising=False)
    monkeypatch.setenv("SAP_AUDIT_SINK_SYSLOG", "127.0.0.1:5514")
    monkeypatch.setenv("SAP_AUDIT_SINK_SYSLOG_TRANSPORT", "udp")
    sinks = build_sinks_from_env()
    assert len(sinks) == 1 and isinstance(sinks[0], SyslogSink)
    assert sinks[0]._cfg.host == "127.0.0.1"
    assert sinks[0]._cfg.port == 5514
    assert sinks[0]._cfg.transport == "udp"


# ── Governance docs ─────────────────────────────────────────────────────────

DOCS = Path(__file__).resolve().parent.parent / "docs"


@pytest.mark.parametrize("name", ["IR_RUNBOOK.md", "SECURITY.md", "COMPLIANCE.md"])
def test_governance_doc_present_and_nontrivial(name):
    p = DOCS / name
    assert p.exists(), name
    text = p.read_text(encoding="utf-8")
    assert len(text) > 800, f"{name} too short ({len(text)} bytes)"


def test_ir_runbook_has_severity_matrix():
    body = (DOCS / "IR_RUNBOOK.md").read_text(encoding="utf-8")
    for level in ("P0", "P1", "P2", "P3"):
        assert level in body
    assert "Detect" in body and "Contain" in body and "Eradicate" in body


def test_compliance_maps_gdpr_iso_soc2():
    body = (DOCS / "COMPLIANCE.md").read_text(encoding="utf-8")
    assert "GDPR" in body
    assert "27001" in body
    assert "SOC 2" in body or "SOC2" in body
    # Cross-reference to the audit log module.
    assert "audit_log.py" in body
