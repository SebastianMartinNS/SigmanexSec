"""
core/observability/tracing.py — OpenTelemetry tracer (lazy, optional).

If ``SAP_OTEL_ENDPOINT`` is unset or the OTEL SDK is not installed, every
``get_tracer().start_as_current_span(...)`` returns a no-op context
manager so the orchestrator can call into it unconditionally.

Configuration env vars:

* ``SAP_OTEL_ENDPOINT`` — OTLP gRPC endpoint (e.g. ``http://otel:4317``)
* ``SAP_OTEL_SERVICE_NAME`` — service.name attribute, default ``sap-pentest``
* ``SAP_OTEL_SAMPLING`` — float 0-1, default 1.0 (always sample)

A reasonable production deploy points the endpoint at a local
otel-collector that fans out to Tempo/Jaeger and the dashboard's Grafana
board (see ``examples/grafana/sap-pentest-dashboard.json`` from Milestone D).
"""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Any

_log = logging.getLogger(__name__)


class _NullSpan:
    def set_attribute(self, *_args: Any, **_kwargs: Any) -> None: ...
    def set_attributes(self, *_args: Any, **_kwargs: Any) -> None: ...
    def record_exception(self, *_args: Any, **_kwargs: Any) -> None: ...
    def add_event(self, *_args: Any, **_kwargs: Any) -> None: ...

    def __enter__(self) -> "_NullSpan":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None


class _NullTracer:
    enabled = False

    @contextlib.contextmanager
    def start_as_current_span(self, _name: str, **_kwargs: Any) -> Any:
        yield _NullSpan()


_TRACER_CACHE: Any | None = None


def get_tracer() -> Any:
    """Return the process tracer; lazily initialize OTLP exporter on first call."""
    global _TRACER_CACHE
    if _TRACER_CACHE is not None:
        return _TRACER_CACHE
    endpoint = os.environ.get("SAP_OTEL_ENDPOINT", "").strip()
    if not endpoint:
        _TRACER_CACHE = _NullTracer()
        return _TRACER_CACHE
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        _log.info(
            "OpenTelemetry SDK not installed; tracing disabled (%s). "
            "Install extras: pip install '.[observability]'",
            exc,
        )
        _TRACER_CACHE = _NullTracer()
        return _TRACER_CACHE
    try:
        service = os.environ.get("SAP_OTEL_SERVICE_NAME", "sap-pentest")
        resource = Resource.create({"service.name": service})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
        )
        trace.set_tracer_provider(provider)
        _TRACER_CACHE = trace.get_tracer("sap-pentest.tracing")
        _log.info("OpenTelemetry tracer enabled, endpoint=%s", endpoint)
        return _TRACER_CACHE
    except Exception as exc:
        _log.warning("OpenTelemetry init failed: %s", exc)
        _TRACER_CACHE = _NullTracer()
        return _TRACER_CACHE
