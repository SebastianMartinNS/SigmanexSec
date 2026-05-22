"""
core/observability/metrics.py — Prometheus counters/gauges/histograms.

Lazy initialization: the first call to :func:`get_metrics` either returns a
populated ``MetricsRegistry`` (when ``prometheus_client`` is importable and
``SAP_METRICS_ENABLED`` is truthy) or a ``_NullMetrics`` shim that silently
absorbs every operation. The shim has identical method names so producers
never branch on ``has_metrics``.

The package exposes a tiny ``metrics_response`` helper that returns a
FastAPI ``Response`` with the Prometheus exposition format. Mounted by
:mod:`sap_dashboard.backend.routes.health` at ``GET /metrics``.

All metric names follow the ``sap_<subsystem>_<unit>`` convention so a
Grafana board can group them with one regex.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Protocol

_log = logging.getLogger(__name__)


def _metrics_enabled() -> bool:
    val = os.environ.get("SAP_METRICS_ENABLED", "1")
    return val not in ("", "0", "false", "False")


class _MetricLike(Protocol):
    def inc(self, amount: float = 1.0) -> None: ...
    def observe(self, value: float) -> None: ...
    def set(self, value: float) -> None: ...
    def labels(self, *args: str, **kwargs: str) -> _MetricLike: ...


class _NullMetric:
    def inc(self, amount: float = 1.0) -> None: ...
    def observe(self, value: float) -> None: ...
    def set(self, value: float) -> None: ...
    def labels(self, *args: str, **kwargs: str) -> _NullMetric:
        return self


class _NullMetrics:
    """No-op registry used when prometheus_client is missing or disabled."""

    def __init__(self) -> None:
        self.enabled = False
        self._null = _NullMetric()

    def __getattr__(self, name: str) -> _NullMetric:
        return self._null

    def render(self) -> tuple[bytes, str]:
        return b"# metrics disabled\n", "text/plain; version=0.0.4; charset=utf-8"


class MetricsRegistry:
    """Concrete Prometheus-backed registry.

    Attribute access (``self.agent_steps_total``) returns the underlying
    metric so callers can chain ``.labels(...).inc()`` directly.
    """

    enabled = True

    def __init__(self, prom_mod: Any) -> None:
        self._prom = prom_mod
        # CollectorRegistry is process-local — distinct instances would
        # collide on metric names, so we always use the default one.
        # Counters --------------------------------------------------------
        self.agent_steps_total = prom_mod.Counter(
            "sap_agent_steps_total",
            "Number of agent ReAct steps emitted, labelled by role and phase",
            ["role", "phase"],
        )
        self.tool_calls_total = prom_mod.Counter(
            "sap_tool_calls_total",
            "Tool dispatch attempts, labelled by tool and outcome",
            ["tool", "status"],
        )
        self.llm_calls_total = prom_mod.Counter(
            "sap_llm_calls_total",
            "LLM completion calls, labelled by provider and model",
            ["provider", "model"],
        )
        self.role_handoffs_total = prom_mod.Counter(
            "sap_role_handoffs_total",
            "Role-to-role handoffs in multi-agent mode",
            ["src", "dst"],
        )
        self.scope_violations_total = prom_mod.Counter(
            "sap_scope_violations_total",
            "Scope or role validator rejections, labelled by tool",
            ["tool", "kind"],
        )
        # Histograms ------------------------------------------------------
        self.llm_latency_seconds = prom_mod.Histogram(
            "sap_llm_latency_seconds",
            "Wall-clock latency of a single LLM chat completion",
            ["provider"],
            buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120),
        )
        self.tool_duration_seconds = prom_mod.Histogram(
            "sap_tool_duration_seconds",
            "Wall-clock duration of a tool dispatch (from entry to exit)",
            ["tool"],
            buckets=(0.1, 0.5, 1, 5, 15, 30, 60, 300, 900, 1800),
        )
        # Gauges ----------------------------------------------------------
        self.active_runs = prom_mod.Gauge(
            "sap_active_runs",
            "Currently-running orchestrator runs",
        )
        self.prompt_tokens = prom_mod.Gauge(
            "sap_prompt_tokens",
            "Tokens of the most recent prompt for the given run",
            ["run_id"],
        )

    def render(self) -> tuple[bytes, str]:
        return (
            self._prom.generate_latest(),
            self._prom.CONTENT_TYPE_LATEST,
        )


_REGISTRY_CACHE: MetricsRegistry | _NullMetrics | None = None


def get_metrics() -> MetricsRegistry | _NullMetrics:
    """Return the process-wide metrics registry.

    First call initializes either a Prometheus-backed registry or a null
    one based on environment + import availability. Subsequent calls
    return the cached instance.
    """
    global _REGISTRY_CACHE
    if _REGISTRY_CACHE is not None:
        return _REGISTRY_CACHE
    if not _metrics_enabled():
        _REGISTRY_CACHE = _NullMetrics()
        return _REGISTRY_CACHE
    try:
        import prometheus_client as _prom
    except ImportError:
        _log.info(
            "prometheus_client not installed; metrics disabled "
            "(install extras: pip install '.[observability]')"
        )
        _REGISTRY_CACHE = _NullMetrics()
        return _REGISTRY_CACHE
    try:
        _REGISTRY_CACHE = MetricsRegistry(_prom)
    except ValueError as exc:
        # Duplicate registration when the module is re-imported in the same
        # process — fall back to a stub so tests that monkey-patch the
        # registry stay green.
        _log.warning("MetricsRegistry duplicate registration: %s", exc)
        _REGISTRY_CACHE = _NullMetrics()
    return _REGISTRY_CACHE


def metrics_response() -> Any:
    """Return a FastAPI ``Response`` exposing the Prometheus exposition.

    Importing ``starlette.responses`` lazily keeps :mod:`core.observability`
    usable outside the dashboard process (e.g. inside MCP servers).
    """
    body, content_type = get_metrics().render()
    try:
        from starlette.responses import Response
    except ImportError:  # pragma: no cover
        return body
    return Response(content=body, media_type=content_type)
