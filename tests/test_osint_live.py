"""Live OSINT accuracy tests — gated behind ``@pytest.mark.live``.

Run with:
    SAP_LIVE_OSINT=1 pytest tests/test_osint_live.py -v -m live

Each test:
  - Skips cleanly if the binary is missing or network is unreachable.
  - Uses tolerant accuracy thresholds to absorb upstream platform churn.
  - Audit-logs PII calls into a tmp directory (no pollution of real logs).

Canary targets (chosen for stability + public legitimacy):
  - username        → ``octocat`` (GitHub mascot, present on dozens of sites)
  - email           → ``octocat@github.com`` (GitHub-published address)
  - domain          → ``example.com`` (RFC 2606 reserved demo domain)

The canaries are written into the engagement scope by the
``live_engagement`` fixture (see ``tests/conftest.py``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests._live_helpers import (
    require_binary,
    require_live,
    require_network,
    run_async,
)


pytestmark = pytest.mark.live


# Canaries — kept in sync with the live_engagement fixture.
CANARY_USERNAME = "octocat"
CANARY_EMAIL = "octocat@github.com"
CANARY_DOMAIN = "example.com"


# ── B.1 sherlock ─────────────────────────────────────────────────────────────

def test_sherlock_live(live_engagement):
    require_live()
    require_binary("sherlock")
    require_network("github.com")

    from mcp_servers.osint_server import sherlock_run

    res = run_async(sherlock_run(
        engagement_id=live_engagement.id,
        username=CANARY_USERNAME,
        timeout=15,
    ))
    assert "error" not in res, res.get("error")
    assert res["target"] == CANARY_USERNAME
    assert res["target_kind"] == "username"
    # Tolerant accuracy: octocat exists on dozens of sites; require ≥3 to
    # absorb single-site outages and rate-limits.
    accounts = res.get("accounts", [])
    assert len(accounts) >= 3, (
        f"sherlock found only {len(accounts)} platforms for octocat — "
        "expected ≥3. Sample: " + str(accounts[:5])
    )
    platforms_lc = {a["platform"].lower() for a in accounts}
    assert any("github" in p for p in platforms_lc), (
        f"sherlock did not find GitHub account for octocat. Platforms: {platforms_lc}"
    )


# ── B.2 maigret ──────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_maigret_live(live_engagement):
    require_live()
    require_binary("maigret")
    require_network()

    from mcp_servers.osint_server import maigret_run

    res = run_async(maigret_run(
        engagement_id=live_engagement.id,
        username=CANARY_USERNAME,
        timeout=20,
    ))
    assert "error" not in res, res.get("error")
    accounts = res.get("accounts", [])
    # maigret covers 3000+ sites; ≥5 is well under the expected hit rate.
    assert len(accounts) >= 5, f"maigret found only {len(accounts)} platforms"


# ── B.3 holehe ───────────────────────────────────────────────────────────────

def test_holehe_live(live_engagement):
    require_live()
    require_binary("holehe")
    require_network()

    from mcp_servers.osint_server import holehe_run

    res = run_async(holehe_run(
        engagement_id=live_engagement.id,
        email=CANARY_EMAIL,
    ))
    assert "error" not in res, res.get("error")
    # Many SaaS sites rate-limit holehe; only require non-crash + correct shape.
    assert res["target"] == CANARY_EMAIL
    assert res["target_kind"] == "email"
    assert isinstance(res.get("accounts"), list)


# ── B.4 h8mail (free sources only) ──────────────────────────────────────────

def test_h8mail_live(live_engagement):
    require_live()
    require_binary("h8mail")
    require_network()

    from mcp_servers.osint_server import h8mail_run

    res = run_async(h8mail_run(
        engagement_id=live_engagement.id,
        email=CANARY_EMAIL,
    ))
    assert "error" not in res, res.get("error")
    assert isinstance(res.get("breaches"), list)
    # h8mail returns 0 with --help-style banners even when no breaches found.
    assert res["exit_code"] in (0, 1, 2)


# ── B.5 whatsmyname ─────────────────────────────────────────────────────────

def test_whatsmyname_live(live_engagement):
    require_live()
    require_binary("whatsmyname")
    require_network()

    from mcp_servers.osint_server import whatsmyname_run

    res = run_async(whatsmyname_run(
        engagement_id=live_engagement.id,
        username=CANARY_USERNAME,
    ))
    assert "error" not in res, res.get("error")
    accounts = res.get("accounts", [])
    # whatsmyname uses a curated dataset; 3 is a very conservative floor.
    assert len(accounts) >= 3 or res["exit_code"] == 0, (
        f"whatsmyname returned no accounts and non-zero exit. "
        f"stdout head: {(res.get('stdout') or '')[:300]}"
    )


# ── B.6 social-analyzer ─────────────────────────────────────────────────────

def test_social_analyzer_live(live_engagement):
    require_live()
    require_binary("social-analyzer")
    require_network()

    from mcp_servers.osint_server import social_analyzer_run

    res = run_async(social_analyzer_run(
        engagement_id=live_engagement.id,
        username=CANARY_USERNAME,
        top=20,
    ))
    assert "error" not in res, res.get("error")
    assert res["exit_code"] == 0
    # Output must be parseable; account count is variable.
    assert isinstance(res.get("accounts"), list)


# ── B.7 ghunt (skip-friendly: requires interactive cookie setup) ────────────

def test_ghunt_live(live_engagement):
    require_live()
    require_binary("ghunt")
    require_network()

    from mcp_servers.osint_server import ghunt_email

    res = run_async(ghunt_email(
        engagement_id=live_engagement.id,
        email=CANARY_EMAIL,
    ))
    if "error" in res:
        pytest.skip(f"ghunt error (likely missing cookie store): {res['error']}")
    if res.get("setup_required"):
        pytest.skip(f"ghunt requires setup: {res['setup_required']}")
    assert res["exit_code"] in (0, 1)


# ── B.8 recon-ng (domain mode → infra scope) ────────────────────────────────

def test_recon_ng_domain_live(live_engagement):
    require_live()
    require_binary("recon-ng")
    require_network()

    from mcp_servers.osint_server import recon_ng_batch

    res = run_async(recon_ng_batch(
        engagement_id=live_engagement.id,
        target=CANARY_DOMAIN,
        kind="domain",
        modules="recon/domains-hosts/hackertarget",
    ))
    assert "error" not in res, res.get("error")
    # recon-ng exits 0 when the resource script completes (regardless of hits).
    assert res["exit_code"] == 0
    stdout = (res.get("stdout") or "").lower()
    # Loose check: the module ran (its name should appear in the run trace).
    assert "hackertarget" in stdout or "recon-ng" in stdout, (
        f"recon-ng stdout missing expected markers: {stdout[:300]}"
    )


# ── B.9 spiderfoot (domain mode) ────────────────────────────────────────────

def test_spiderfoot_domain_live(live_engagement):
    require_live()
    require_binary("sf")
    require_network()

    from mcp_servers.osint_server import spiderfoot_batch

    res = run_async(spiderfoot_batch(
        engagement_id=live_engagement.id,
        target=CANARY_DOMAIN,
        kind="domain",
        modules="sfp_dnsresolve",
    ))
    assert "error" not in res, res.get("error")
    assert res["exit_code"] in (0, 1)


# ── B.10 recon-ng (identity mode → identity scope) ──────────────────────────

def test_recon_ng_identity_live(live_engagement):
    require_live()
    require_binary("recon-ng")
    require_network()

    from mcp_servers.osint_server import recon_ng_batch

    res = run_async(recon_ng_batch(
        engagement_id=live_engagement.id,
        target=CANARY_USERNAME,
        kind="username",
        # A no-op-style passive module sufficient to exercise the identity
        # scope path; we don't require module success, only scope acceptance.
        modules="recon/profiles-profiles/profiler",
    ))
    # Either runs (module installed) or exits non-zero (module missing in
    # local recon-ng installation). Both prove identity scope passed.
    if "error" in res:
        # The only acceptable error here is recon-ng failing to load the
        # module — NOT a scope rejection.
        assert "scope" not in res["error"].lower(), res["error"]


# ── B.11 audit smoke: PII flag is logged ────────────────────────────────────

def test_pii_audit_logged_live(live_engagement, tmp_paths):
    """End-to-end: a live sherlock call must produce a pii=true audit entry."""
    require_live()
    require_binary("sherlock")
    require_network("github.com")

    from mcp_servers.osint_server import sherlock_run

    res = run_async(sherlock_run(
        engagement_id=live_engagement.id,
        username=CANARY_USERNAME,
        timeout=10,
    ))
    assert "error" not in res, res.get("error")

    audit_path = Path(os.environ["AUDIT_LOG_PATH"])
    assert audit_path.exists(), "audit log not created"
    lines = audit_path.read_text().splitlines()
    pii_entries = []
    for line in lines:
        if not line.strip():
            continue
        e = json.loads(line)
        details = e.get("details") or {}
        if (
            details.get("pii") is True
            and details.get("identity_kind") == "username"
            and e.get("target") == CANARY_USERNAME
        ):
            pii_entries.append(e)
    assert len(pii_entries) >= 1, (
        f"no pii=true audit entry found for {CANARY_USERNAME}. "
        f"Total entries: {len(lines)}. "
        f"Sample last entry: {lines[-1] if lines else '(empty)'}"
    )
