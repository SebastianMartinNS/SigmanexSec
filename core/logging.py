"""
core/logging.py — Structured operational logging for SAP-Pentest.

This module is **distinct from `core/audit_log.py`**. They serve different
purposes and must not be confused:

* ``core/audit_log.py`` is the canonical, hash-chained, tamper-evident
  trail of privileged actions (tool execution, sudo unlock, scope
  rejection, RBAC denial). It is append-only, BLAKE2b-chained, and
  mirrored to external sinks for compliance.

* ``core/logging.py`` (this file) is the operational telemetry channel —
  "what is the process doing right now?". It captures debug traces,
  warnings, exceptions, and lifecycle events through ``structlog``.
  Records are line-delimited JSON (in containers / CI) or
  human-readable coloured output (in an interactive TTY), and may be
  rotated or discarded freely.

Usage::

    from core.logging import configure_logging, get_logger
    configure_logging()                  # idempotent; safe to call multiple times
    log = get_logger("orchestrator")
    log.info("agent.run.start", engagement_id=eng_id, iteration=0)

Environment knobs:

* ``SAP_LOG_LEVEL``   ``DEBUG`` | ``INFO`` (default) | ``WARNING`` | ``ERROR``
* ``SAP_LOG_FORMAT``  ``json`` (forced JSON) | ``console`` (forced human) |
  unset → JSON when stderr is not a TTY, console otherwise.

Correlation-id propagation
--------------------------

``CorrelationIdMiddleware`` reads or generates the ``X-Correlation-Id``
header on every HTTP request, stores it in a contextvar, binds it on
every structlog record emitted during the request, and echoes it back
in the response header so downstream HTTP/MCP calls can chain the id.

For non-HTTP entry points (CLI, orchestrator run), call
``new_correlation_id()`` and ``bind_correlation_id(cid)`` to anchor a
trace through the run.
"""

from __future__ import annotations

import logging as stdlib_logging
import os
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

CORRELATION_HEADER = "X-Correlation-Id"

correlation_id_var: ContextVar[str | None] = ContextVar(
    "sap_correlation_id", default=None
)

_configured = False


def _level_from_env() -> int:
    name = os.environ.get("SAP_LOG_LEVEL", "INFO").upper().strip()
    return int(getattr(stdlib_logging, name, stdlib_logging.INFO))


def _json_mode_default() -> bool:
    fmt = os.environ.get("SAP_LOG_FORMAT", "").lower().strip()
    if fmt == "json":
        return True
    if fmt == "console":
        return False
    # Heuristic: JSON when not attached to a TTY (CI, systemd, container).
    return not sys.stderr.isatty()


def _correlation_processor(
    _logger: Any, _method: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    cid = correlation_id_var.get()
    if cid and "correlation_id" not in event_dict:
        event_dict["correlation_id"] = cid
    return event_dict


def configure_logging(
    *,
    level: int | None = None,
    json_output: bool | None = None,
    service: str | None = None,
) -> None:
    """Initialise structlog + stdlib logging. Idempotent."""
    global _configured
    if _configured:
        return

    lvl = level if level is not None else _level_from_env()
    json_out = json_output if json_output is not None else _json_mode_default()

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _correlation_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: Any
    if json_out:
        renderer = structlog.processors.JSONRenderer(sort_keys=True)
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    # Use a dynamic factory that re-reads ``sys.stderr`` on every emit and
    # disable per-logger caching: pytest's ``capsys`` and similar fixtures
    # swap ``sys.stderr`` between tests, so a cached factory that captured
    # the original file descriptor will raise ``ValueError: I/O operation
    # on closed file`` once that fixture tears down.
    def _factory(name: str | None = None) -> Any:
        return structlog.PrintLogger(file=sys.stderr)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        context_class=dict,
        logger_factory=_factory,
        cache_logger_on_first_use=False,
    )

    # Bridge stdlib loggers (uvicorn, fastapi, anthropic) into the same
    # output sink so operators see a single coherent stream.
    stdlib_logging.basicConfig(
        level=lvl,
        format="%(message)s",
        handlers=[stdlib_logging.StreamHandler(sys.stderr)],
        force=True,
    )

    if service:
        structlog.contextvars.bind_contextvars(service=service)
    _configured = True


def get_logger(name: str | None = None) -> Any:
    """Return a structlog BoundLogger; auto-configures on first call."""
    if not _configured:
        configure_logging()
    return structlog.get_logger(name or "sap")


def new_correlation_id() -> str:
    """Generate a fresh hex correlation id."""
    return uuid.uuid4().hex


def bind_correlation_id(cid: str) -> None:
    """Bind a correlation id to the current async/thread context."""
    correlation_id_var.set(cid)


def current_correlation_id() -> str | None:
    """Return the correlation id bound to the current context, if any."""
    return correlation_id_var.get()


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Bind ``X-Correlation-Id`` to a contextvar for the duration of the request.

    Reads the incoming header if present (operator may have set it for
    distributed tracing), otherwise generates a new one. Echoes the value
    back in the response so downstream MCP / HTTP calls share the id.
    """

    def __init__(self, app: ASGIApp, header_name: str = CORRELATION_HEADER) -> None:
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        incoming = request.headers.get(self.header_name)
        cid = incoming or new_correlation_id()
        token = correlation_id_var.set(cid)
        try:
            response: Response = await call_next(request)
        finally:
            correlation_id_var.reset(token)
        response.headers[self.header_name] = cid
        return response
