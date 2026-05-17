"""
core/audit_sink.py — External, write-only audit sink (P5).

Tamper-evident audit-log shipping. The local `logs/audit.jsonl` is fine
for liveness investigation, but for SOC2/ISO27001 we need a *separate*
sink that the operator account cannot rewrite. This module provides:

  * `SyslogSink`   — RFC 5424 syslog over UDP / TCP / TLS to a remote
                     collector (rsyslog, Vector, Loki, Splunk, …).
  * `FileSink`     — append-only file on a different filesystem owned by
                     a different uid (e.g., a mount with chattr +a).

Both sinks share a `BaseSink.emit(line)` contract — they receive the
already-hashed JSONL line so the chain integrity is preserved end-to-end.

Wired in `core/audit_log.py::AuditLog._writer_loop` after the local file
write: every line is fanned out to all configured sinks; failures are
logged but never block the local write (defense in depth, not a blocker).
"""
from __future__ import annotations

import logging
import os
import socket
import ssl
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


class BaseSink(ABC):
    """Common interface — `emit` MUST never raise on transport failure."""

    @abstractmethod
    def emit(self, line: str) -> None: ...

    def close(self) -> None:  # noqa: B027 — intentional no-op default; concrete sinks override only if they hold state
        """Optional graceful shutdown."""


# ── Append-only file sink ───────────────────────────────────────────────────

class FileSink(BaseSink):
    """Mirror to a separate, append-only file.

    Recommended deployment: a mount owned by `auditor:auditor` with
    `chattr +a` (append only) so the sap user cannot rewrite history.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        # Best-effort: create the file with 0600.
        if not self._path.exists():
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)

    def emit(self, line: str) -> None:
        try:
            with self._lock, open(self._path, "a", encoding="utf-8") as f:
                if not line.endswith("\n"):
                    line += "\n"
                f.write(line)
                f.flush()
        except OSError as exc:
            log.warning("FileSink emit failed: %s", exc)


# ── Syslog sink (RFC 5424) ──────────────────────────────────────────────────

@dataclass
class SyslogConfig:
    host: str
    port: int = 6514
    transport: str = "tls"   # one of: udp / tcp / tls
    facility: int = 13       # log_audit
    severity: int = 5        # notice
    cafile: str | None = None
    timeout_s: float = 2.0


class SyslogSink(BaseSink):
    """RFC 5424 framed messages over UDP/TCP/TLS.

    Connections are lazy and reconnect on failure. Drops on transport
    error to avoid blocking audit-write throughput. The local file
    remains the source of truth.
    """

    def __init__(self, cfg: SyslogConfig):
        self._cfg = cfg
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._hostname = socket.gethostname()

    def _connect(self) -> socket.socket | None:
        c = self._cfg
        try:
            if c.transport == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(c.timeout_s)
                s.connect((c.host, c.port))
                return s
            if c.transport in ("tcp", "tls"):
                s = socket.create_connection((c.host, c.port), timeout=c.timeout_s)
                if c.transport == "tls":
                    ctx = ssl.create_default_context(cafile=c.cafile)
                    s = ctx.wrap_socket(s, server_hostname=c.host)
                return s
        except (OSError, ssl.SSLError) as exc:
            log.warning("SyslogSink connect failed: %s", exc)
            return None
        return None

    def _format(self, line: str) -> bytes:
        c = self._cfg
        pri = c.facility * 8 + c.severity
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # RFC5424: <PRI>1 TS HOST APP PID MSGID STRUCTURED-DATA MSG
        msg = f"<{pri}>1 {ts} {self._hostname} sap-audit - - - {line.rstrip()}\n"
        if c.transport in ("tcp", "tls"):
            # Octet counting framing (RFC 6587).
            payload = msg.encode("utf-8")
            return f"{len(payload)} ".encode() + payload
        return msg.encode("utf-8")

    def emit(self, line: str) -> None:
        with self._lock:
            if self._sock is None:
                self._sock = self._connect()
            if self._sock is None:
                return
            try:
                self._sock.sendall(self._format(line))
            except (OSError, ssl.SSLError) as exc:
                log.warning("SyslogSink send failed: %s", exc)
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None


# ── Factory from environment ────────────────────────────────────────────────

def build_sinks_from_env() -> list[BaseSink]:
    """Build sinks from ``SAP_AUDIT_SINK_*`` env vars.

    * ``SAP_AUDIT_SINK_FILE``     → path to an append-only mirror file.
    * ``SAP_AUDIT_SINK_SYSLOG``   → ``host:port`` for syslog target.
    * ``SAP_AUDIT_SINK_SYSLOG_TRANSPORT`` → ``udp`` / ``tcp`` / ``tls``.
    * ``SAP_AUDIT_SINK_SYSLOG_CA`` → CA bundle for TLS verification.
    """
    sinks: list[BaseSink] = []
    p = os.environ.get("SAP_AUDIT_SINK_FILE")
    if p:
        sinks.append(FileSink(p))
    h = os.environ.get("SAP_AUDIT_SINK_SYSLOG")
    if h:
        host, _, port_s = h.partition(":")
        port = int(port_s) if port_s else 6514
        transport = os.environ.get("SAP_AUDIT_SINK_SYSLOG_TRANSPORT", "tls").lower()
        cafile = os.environ.get("SAP_AUDIT_SINK_SYSLOG_CA") or None
        sinks.append(SyslogSink(SyslogConfig(
            host=host, port=port, transport=transport, cafile=cafile,
        )))
    return sinks
