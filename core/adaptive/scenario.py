"""
core/adaptive/scenario.py — Deterministic scenario classifier.

Maps the *static* engagement scope plus any *observed* services/findings
to a high-level scenario tag (`web`, `network`, `ad`, `mixed`) that the
playbook router uses to pick a tactical template.

Why deterministic rules instead of an LLM call:
- Reproducible (same input -> same output).
- Cheap and audit-friendly (every match is a named indicator).
- Survives offline/air-gapped engagements where the LLM is unavailable.

The classifier never narrows scope; it only tags it. The orchestrator may
choose to ignore the recommendation depending on the configured rollout
mode (off / shadow / advisory / enforce).
"""
from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

# Service/port tuples that strongly indicate Active Directory infrastructure.
_AD_PORTS = {88, 389, 445, 636, 3268, 3269, 5985, 5986}
_AD_SERVICE_TOKENS = (
    "kerberos", "ldap", "microsoft-ds", "smb", "msrpc", "wsman", "winrm",
    "active directory",
)
_HTTP_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9090}
_HTTP_SERVICE_TOKENS = ("http", "https", "ssl/http", "http-proxy")


def _confidence_floor() -> float:
    """Minimum confidence to keep a *non-mixed* classification.

    Anything below this gets demoted to ``mixed`` so the playbook router
    falls back to the generic template instead of committing to a wrong
    scenario on weak evidence. Tunable via ``SAP_SCENARIO_MIN_CONFIDENCE``
    (default 0.30, the historical clamp value).
    """
    try:
        v = float(os.environ.get("SAP_SCENARIO_MIN_CONFIDENCE", "0.30"))
    except (TypeError, ValueError):
        return 0.30
    return max(0.0, min(1.0, v))


@dataclass(frozen=True)
class Scenario:
    """High-level target classification used to pick a playbook."""
    type: str                         # "web" | "network" | "ad" | "mixed"
    confidence: float                 # 0.0–1.0
    indicators: tuple[str, ...] = field(default_factory=tuple)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "confidence": round(self.confidence, 3),
            "indicators": list(self.indicators),
            "rationale": self.rationale,
        }


def _service_matches(svc: dict, tokens: Iterable[str]) -> bool:
    blob = " ".join(
        str(svc.get(k, "")) for k in ("service", "banner", "version", "name")
    ).lower()
    return any(t in blob for t in tokens)


def _flatten_services(hosts: Sequence[dict]) -> list[dict]:
    services: list[dict] = []
    for h in hosts or []:
        for s in (h.get("services") or []):
            if isinstance(s, dict):
                services.append(s)
    return services


class ScenarioClassifier:
    """Stateless deterministic classifier."""

    @staticmethod
    def classify(
        scope: dict | None = None,
        hosts: Sequence[dict] | None = None,
        findings: Sequence[dict] | None = None,
    ) -> Scenario:
        scope = scope or {}
        hosts = list(hosts or [])
        findings = list(findings or [])

        urls = scope.get("scope_urls") or []
        cidrs = scope.get("scope_cidrs") or []
        domains = scope.get("scope_domains") or []
        services = _flatten_services(hosts)

        # Indicator tallies (each adds weight to its scenario).
        web_weight = 0.0
        network_weight = 0.0
        ad_weight = 0.0
        indicators: list[str] = []

        # ── Static scope signals ──────────────────────────────────────
        if urls:
            web_weight += 0.55
            indicators.append(f"scope_urls={len(urls)}")
        if cidrs:
            network_weight += 0.40
            indicators.append(f"scope_cidrs={len(cidrs)}")
        if domains and not urls:
            # Domains without explicit URLs: lean network/AD until proven web.
            network_weight += 0.10
            indicators.append(f"scope_domains={len(domains)}")

        # ── Observed services ─────────────────────────────────────────
        ad_hits = 0
        http_hits = 0
        for svc in services:
            try:
                port = int(svc.get("port", 0))
            except (TypeError, ValueError):
                port = 0
            if port in _AD_PORTS or _service_matches(svc, _AD_SERVICE_TOKENS):
                ad_hits += 1
            if port in _HTTP_PORTS or _service_matches(svc, _HTTP_SERVICE_TOKENS):
                http_hits += 1
        if ad_hits:
            ad_weight += min(0.60, 0.20 + 0.15 * ad_hits)
            indicators.append(f"ad_services={ad_hits}")
        if http_hits:
            web_weight += min(0.45, 0.15 + 0.10 * http_hits)
            indicators.append(f"http_services={http_hits}")
        if services and not (ad_hits or http_hits):
            network_weight += 0.10
            indicators.append(f"generic_services={len(services)}")

        # ── Findings hints ────────────────────────────────────────────
        finding_categories = {str(f.get("category", "")).lower() for f in findings}
        if finding_categories & {"sql_injection", "cross_site_scripting", "authentication_bypass"}:
            web_weight += 0.10
            indicators.append("web_findings")
        if "active_directory" in finding_categories:
            ad_weight += 0.20
            indicators.append("ad_findings")

        weights = {"web": web_weight, "network": network_weight, "ad": ad_weight}
        if not any(weights.values()):
            return Scenario(
                type="mixed",
                confidence=0.20,
                indicators=("empty_scope",),
                rationale="no scope/service evidence available; defaulting to mixed",
            )

        # Sort and decide between dominant and mixed.
        ranked = sorted(weights.items(), key=lambda kv: kv[1], reverse=True)
        top_kind, top_weight = ranked[0]
        runner_up_weight = ranked[1][1]

        # Mixed when top is not clearly ahead of the runner-up.
        if top_weight > 0 and runner_up_weight / max(top_weight, 1e-9) >= 0.75:
            confidence = min(0.85, 0.35 + (top_weight + runner_up_weight) / 2)
            return Scenario(
                type="mixed",
                confidence=confidence,
                indicators=tuple(indicators),
                rationale=f"top={top_kind}({top_weight:.2f}) close to runner-up({runner_up_weight:.2f})",
            )

        # Map raw weight to confidence (saturate near 0.95).
        confidence = max(0.30, min(0.95, 0.35 + top_weight))
        floor = _confidence_floor()
        if confidence < floor:
            # Weak evidence — refuse to commit to a specialised playbook.
            return Scenario(
                type="mixed",
                confidence=confidence,
                indicators=tuple(indicators) + (f"below_threshold={floor:.2f}",),
                rationale=(
                    f"top={top_kind} weight={top_weight:.2f} confidence={confidence:.2f} "
                    f"below floor {floor:.2f}; falling back to mixed"
                ),
            )
        return Scenario(
            type=top_kind,
            confidence=confidence,
            indicators=tuple(indicators),
            rationale=f"dominant={top_kind} weight={top_weight:.2f}",
        )
