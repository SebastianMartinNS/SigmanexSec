"""Tests for ScenarioClassifier and AdaptiveSettings."""
from __future__ import annotations

import pytest

from core.adaptive import (
    AdaptiveSettings,
    RolloutMode,
    ScenarioClassifier,
    load_adaptive_settings,
)


def test_classifier_picks_web_for_url_scope():
    s = ScenarioClassifier.classify(
        scope={"scope_urls": ["https://app.example.com"]},
    )
    assert s.type == "web"
    assert s.confidence > 0.6
    assert any("scope_urls" in i for i in s.indicators)


def test_classifier_picks_network_for_cidr_only():
    s = ScenarioClassifier.classify(
        scope={"scope_cidrs": ["10.0.0.0/24"]},
    )
    assert s.type == "network"
    assert s.confidence > 0.5


def test_classifier_picks_ad_when_smb_and_kerberos_present():
    hosts = [{
        "ip": "10.0.0.10",
        "services": [
            {"port": 88, "service": "kerberos"},
            {"port": 445, "service": "microsoft-ds"},
            {"port": 389, "service": "ldap"},
        ],
    }]
    s = ScenarioClassifier.classify(
        scope={"scope_cidrs": ["10.0.0.0/24"]},
        hosts=hosts,
    )
    assert s.type == "ad"
    assert s.confidence > 0.6
    assert any("ad_services" in i for i in s.indicators)


def test_classifier_returns_mixed_when_signals_balanced():
    # CIDR scope (network signal) plus services that split between web and AD,
    # so no single weight clearly dominates.
    hosts = [{
        "services": [
            {"port": 80, "service": "http"},
            {"port": 445, "service": "microsoft-ds"},
        ],
    }]
    s = ScenarioClassifier.classify(
        scope={"scope_cidrs": ["10.0.0.0/24"]},
        hosts=hosts,
    )
    assert s.type == "mixed"


def test_classifier_handles_empty_scope():
    s = ScenarioClassifier.classify()
    assert s.type == "mixed"
    assert s.confidence < 0.5


def test_settings_loader_uses_repo_config_by_default():
    settings = load_adaptive_settings()
    # config.yaml ships with adaptive.enabled=true and rollout_mode=shadow.
    assert isinstance(settings, AdaptiveSettings)
    assert settings.enabled is True
    assert settings.rollout_mode in {RolloutMode.SHADOW, RolloutMode.ADVISORY, RolloutMode.ENFORCE, RolloutMode.OFF}
    assert "web" in settings.enabled_scenarios


def test_settings_loader_falls_back_when_file_missing(tmp_path):
    settings = load_adaptive_settings(tmp_path / "missing.yaml")
    assert settings.enabled is False
    assert settings.rollout_mode is RolloutMode.OFF


def test_settings_phase_threshold_lookup(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "adaptive:\n"
        "  enabled: true\n"
        "  rollout_mode: advisory\n"
        "  confidence:\n"
        "    default_score: 0.4\n"
        "    phase_thresholds:\n"
        "      reconnaissance: 0.5\n"
        "      exploitation: 0.8\n"
    )
    settings = load_adaptive_settings(cfg)
    assert settings.is_active
    assert settings.threshold_for("reconnaissance") == pytest.approx(0.5)
    assert settings.threshold_for("exploitation") == pytest.approx(0.8)
    # Unknown phase falls back to the default score.
    assert settings.threshold_for("unknown") == pytest.approx(0.4)
