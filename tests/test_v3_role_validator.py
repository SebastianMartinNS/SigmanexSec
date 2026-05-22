"""
tests/test_v3_role_validator.py — Milestone C1+C2 acceptance.

Verifies the role catalog loads cleanly and the RoleValidator chokepoint
correctly admits / rejects tools, phases, and handoffs for every role
shipped with v3.0.
"""
from __future__ import annotations

import pytest

from agent.roles import get_registry
from core.models import Phase
from core.role_validator import RoleValidator, RoleViolation, get_role_validator


# ── Registry --------------------------------------------------------------


def test_registry_loads_six_roles():
    r = get_registry()
    assert {"planner", "recon_analyst", "exploit_dev",
            "post_exploit_operator", "blueteam_observer", "reporter"} == set(r.all_ids())


def test_every_handoff_target_is_known():
    r = get_registry()
    known = set(r.all_ids())
    for role in r.all_roles():
        for edge in role.can_handoff_to:
            assert edge.to in known, f"{role.id} → {edge.to} not in catalog"


def test_every_persona_prompt_exists_on_disk():
    """Loader validates this at startup; this test guards against silent
    deletions of one of the 6 persona files."""
    from pathlib import Path
    repo_root = Path(__file__).resolve().parents[1]
    for role in get_registry().all_roles():
        assert (repo_root / role.persona_prompt_path).is_file(), \
            f"{role.id}: missing persona file at {role.persona_prompt_path}"


def test_high_stakes_roles_require_human_approval():
    """ExploitDev and PostExploitOperator must default to human-in-the-loop."""
    r = get_registry()
    assert r.require("exploit_dev").capability_guards.requires_human_approval
    assert r.require("post_exploit_operator").capability_guards.requires_human_approval
    # Read-only roles do not require approval.
    assert not r.require("reporter").capability_guards.requires_human_approval
    assert not r.require("blueteam_observer").capability_guards.requires_human_approval


# ── RoleValidator: tools --------------------------------------------------


def test_recon_can_run_nmap():
    v = get_role_validator()
    assert v is not None
    v.assert_tool_allowed("recon_analyst", "nmap_scan")  # does not raise


def test_recon_blocked_from_metasploit_via_denylist():
    v = get_role_validator()
    with pytest.raises(RoleViolation, match="explicitly denied"):
        v.assert_tool_allowed("recon_analyst", "metasploit_module")


def test_reporter_cannot_scan():
    v = get_role_validator()
    with pytest.raises(RoleViolation):
        v.assert_tool_allowed("reporter", "nmap_scan")


def test_unknown_tool_blocked_when_not_in_allowed():
    v = get_role_validator()
    with pytest.raises(RoleViolation, match="not allowed to invoke"):
        v.assert_tool_allowed("planner", "made_up_tool_xyz")


def test_unknown_role_blocked():
    v = get_role_validator()
    with pytest.raises(RoleViolation, match="unknown role"):
        v.assert_tool_allowed("ghost_agent", "nmap_scan")


# ── RoleValidator: phases -------------------------------------------------


def test_exploit_dev_blocked_in_recon_phase():
    v = get_role_validator()
    with pytest.raises(RoleViolation, match="not allowed in phase"):
        v.assert_phase_allowed("exploit_dev", Phase.RECON)


def test_blueteam_allowed_in_post_scoping_phases():
    """Blueteam observer follows the offensive specialists through every
    PTES phase from reconnaissance onward — but not scoping (that is a
    contractual phase, not a technical one)."""
    v = get_role_validator()
    for phase in (Phase.RECON, Phase.SCANNING, Phase.EXPLOITATION,
                  Phase.POST_EXPLOIT, Phase.REPORTING):
        v.assert_phase_allowed("blueteam_observer", phase)
    with pytest.raises(RoleViolation):
        v.assert_phase_allowed("blueteam_observer", Phase.SCOPING)


def test_phase_validator_accepts_strings():
    v = get_role_validator()
    v.assert_phase_allowed("exploit_dev", "exploitation")
    with pytest.raises(RoleViolation):
        v.assert_phase_allowed("exploit_dev", "reconnaissance")


# ── RoleValidator: handoffs ----------------------------------------------


def test_recon_can_handoff_to_exploit():
    v = get_role_validator()
    v.assert_handoff_allowed("recon_analyst", "exploit_dev")


def test_reporter_cannot_handoff():
    """Reporter is terminal: no outgoing handoff edges."""
    v = get_role_validator()
    with pytest.raises(RoleViolation):
        v.assert_handoff_allowed("reporter", "planner")


def test_handoff_to_unknown_role_blocked():
    v = get_role_validator()
    with pytest.raises(RoleViolation, match="not a registered role"):
        v.assert_handoff_allowed("planner", "ghost_agent")
