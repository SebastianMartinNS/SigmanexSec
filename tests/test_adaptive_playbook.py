"""Tests for the PlaybookRouter and the YAML templates shipped under playbooks/."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.adaptive import PlaybookNotFound, PlaybookRouter, render_advisory

_REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset_playbook_cache():
    PlaybookRouter.reset_cache()
    yield
    PlaybookRouter.reset_cache()


def test_router_lists_built_in_scenarios():
    scenarios = PlaybookRouter.list_scenarios()
    assert {"web", "network", "ad", "mixed"}.issubset(set(scenarios))


@pytest.mark.parametrize("scenario", ["web", "network", "ad", "mixed"])
def test_router_loads_each_built_in_template(scenario):
    pb = PlaybookRouter.load(scenario)
    assert pb.scenario == scenario
    # All templates ship with at least the recon phase populated.
    assert pb.steps_for_phase("reconnaissance"), f"{scenario}: empty recon"
    # All templates ship with a fallback chain for the most common failure modes.
    assert pb.fallback_for("timeout")


def test_router_raises_for_unknown_scenario():
    with pytest.raises(PlaybookNotFound):
        PlaybookRouter.load("does_not_exist")


def test_router_load_or_none_returns_none_for_unknown():
    assert PlaybookRouter.load_or_none("does_not_exist") is None


def test_router_uses_custom_directory(tmp_path):
    (tmp_path / "custom.yaml").write_text(
        "scenario: custom\n"
        "description: tiny\n"
        "phases:\n"
        "  reconnaissance:\n"
        "    - tool: my_tool\n"
        "      rationale: probe\n"
        "fallback_chain:\n"
        "  timeout: [abort]\n"
    )
    pb = PlaybookRouter.load("custom", base_dir=tmp_path)
    steps = pb.steps_for_phase("reconnaissance")
    assert len(steps) == 1
    assert steps[0].tool == "my_tool"
    assert pb.fallback_for("timeout") == ("abort",)


def test_render_advisory_is_compact_text():
    pb = PlaybookRouter.load("web")
    text = render_advisory(pb, phase="reconnaissance", max_steps=3)
    assert text.startswith("# Tactical playbook: web")
    assert "Suggested next steps" in text
    assert "Fallback chain" in text
    # Should respect the max_steps cap.
    listed = [line for line in text.splitlines() if line.lstrip().startswith(("1.", "2.", "3.", "4."))]
    assert len(listed) <= 3
