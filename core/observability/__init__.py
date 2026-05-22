"""
core/observability/ — v3.0 metrics + tracing surface.

Both submodules degrade to no-ops when their respective dependency is
missing or the corresponding env switch is off, so the orchestrator and
MCP servers can call into this package unconditionally.

Public API:

    from core.observability import (
        get_metrics,         # MetricsRegistry (Prometheus or null)
        get_tracer,          # OTEL tracer or null tracer
        metrics_response,    # /metrics endpoint helper
    )
"""
from __future__ import annotations

from core.observability.metrics import get_metrics, metrics_response
from core.observability.tracing import get_tracer

__all__ = ["get_metrics", "get_tracer", "metrics_response"]
