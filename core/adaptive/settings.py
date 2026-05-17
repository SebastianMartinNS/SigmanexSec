"""
core/adaptive/settings.py — Adaptive layer configuration loader.

Reads the ``adaptive:`` block from ``config.yaml`` and exposes a small,
typed view that the orchestrator can query without importing YAML on
every call. The loader is best-effort: if the file is missing or
malformed the layer falls back to ``RolloutMode.OFF`` so the legacy
execution path is preserved.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import yaml

_log = logging.getLogger(__name__)
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CONFIG = _REPO_ROOT / "config.yaml"


class RolloutMode(StrEnum):
    OFF = "off"
    SHADOW = "shadow"
    ADVISORY = "advisory"
    ENFORCE = "enforce"

    @classmethod
    def parse(cls, value: object) -> RolloutMode:
        if isinstance(value, RolloutMode):
            return value
        try:
            return cls(str(value).strip().lower())
        except (TypeError, ValueError):
            return cls.OFF


@dataclass(frozen=True)
class AdaptiveSettings:
    enabled: bool = False
    rollout_mode: RolloutMode = RolloutMode.OFF
    emit_decision_audit: bool = True
    confidence_default: float = 0.5
    phase_thresholds: dict[str, float] = field(default_factory=dict)
    enabled_scenarios: tuple[str, ...] = ("web", "network", "ad", "mixed")
    fallback_chain: dict[str, tuple[str, ...]] = field(default_factory=dict)
    auto_pivot: bool = True
    max_pivots_per_run: int = 3
    verification_enabled: bool = False
    drift_penalty: float = 0.20
    confirm_bonus: float = 0.10

    @property
    def is_active(self) -> bool:
        return self.enabled and self.rollout_mode is not RolloutMode.OFF

    def threshold_for(self, phase: str) -> float:
        return float(self.phase_thresholds.get(phase, self.confidence_default))

    def scenario_allowed(self, scenario: str) -> bool:
        return scenario in self.enabled_scenarios


def _coerce_chain(raw: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, tuple[str, ...]] = {}
    for k, v in raw.items():
        if isinstance(v, (list, tuple)):
            out[str(k)] = tuple(str(x) for x in v)
    return out


def _coerce_thresholds(raw: object, default: float) -> dict[str, float]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, float] = {}
    for k, v in raw.items():
        try:
            out[str(k)] = float(v)
        except (TypeError, ValueError):
            out[str(k)] = default
    return out


def load_adaptive_settings(path: os.PathLike | None = None) -> AdaptiveSettings:
    cfg_path = Path(path or os.environ.get("SAP_CONFIG_PATH") or _DEFAULT_CONFIG)
    if not cfg_path.exists():
        return AdaptiveSettings()
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        _log.warning("adaptive settings: failed to parse %s: %s", cfg_path, exc)
        return AdaptiveSettings()

    block = data.get("adaptive") or {}
    if not isinstance(block, dict):
        return AdaptiveSettings()

    enabled = bool(block.get("enabled", False))
    rollout = RolloutMode.parse(block.get("rollout_mode", "off"))
    emit_audit = bool(block.get("emit_decision_audit", True))

    confidence_block = block.get("confidence") or {}
    default_score = float(confidence_block.get("default_score", 0.5))
    thresholds = _coerce_thresholds(
        confidence_block.get("phase_thresholds"), default=default_score
    )

    playbooks_block = block.get("playbooks") or {}
    scenarios = playbooks_block.get("enabled_scenarios") or ("web", "network", "ad", "mixed")
    if not isinstance(scenarios, (list, tuple)):
        scenarios = ("web", "network", "ad", "mixed")
    fallback = _coerce_chain(playbooks_block.get("fallback_chain"))

    repetition = block.get("repetition") or {}
    auto_pivot = bool(repetition.get("auto_pivot", True))
    max_pivots = int(repetition.get("max_pivots_per_run", 3))

    verification = block.get("verification") or {}
    return AdaptiveSettings(
        enabled=enabled,
        rollout_mode=rollout,
        emit_decision_audit=emit_audit,
        confidence_default=default_score,
        phase_thresholds=thresholds,
        enabled_scenarios=tuple(str(s) for s in scenarios),
        fallback_chain=fallback,
        auto_pivot=auto_pivot,
        max_pivots_per_run=max_pivots,
        verification_enabled=bool(verification.get("enabled", False)),
        drift_penalty=float(verification.get("drift_penalty", 0.20)),
        confirm_bonus=float(verification.get("confirm_bonus", 0.10)),
    )
