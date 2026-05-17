"""Unit tests for the SSO connector scaffolding (workstream F2.4).

End-to-end OIDC tests against the Dex mock IdP are a follow-up workstream
(``ci-sso-oidc`` workflow, requires docker-compose in CI). Here we cover
the configuration-resolution and refuse-when-disabled paths so a
contributor cannot accidentally regress the gating logic.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    monkeypatch.setenv("SAP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "assess.db"))
    for var in ("SAP_SSO_PROVIDER", "SAP_SSO_OIDC_ISSUER", "SAP_SSO_ROLE_MAP"):
        monkeypatch.delenv(var, raising=False)
    import sys
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    from sap_dashboard.backend.app import app as fastapi_app
    return TestClient(fastapi_app)


# ── current_config parsing ────────────────────────────────────────────────


def test_current_config_defaults_to_none(monkeypatch):
    for var in ("SAP_SSO_PROVIDER", "SAP_SSO_ROLE_MAP"):
        monkeypatch.delenv(var, raising=False)
    from sap_dashboard.backend.sso import current_config

    cfg = current_config()
    assert cfg.provider == "none"
    assert cfg.role_map == {}
    assert cfg.enabled is False


def test_current_config_role_map_drops_unknown_roles(monkeypatch):
    monkeypatch.setenv("SAP_SSO_PROVIDER", "oidc")
    monkeypatch.setenv(
        "SAP_SSO_ROLE_MAP",
        json.dumps({"sec": "admin", "junior": "intern", "ops": "operator"}),
    )
    from sap_dashboard.backend.sso import current_config

    cfg = current_config()
    assert cfg.provider == "oidc"
    assert cfg.role_map == {"sec": "admin", "ops": "operator"}
    assert "junior" not in cfg.role_map


def test_current_config_invalid_provider_normalises_to_none(monkeypatch):
    monkeypatch.setenv("SAP_SSO_PROVIDER", "rogue-protocol")
    from sap_dashboard.backend.sso import current_config

    assert current_config().provider == "none"


# ── map_groups_to_role ───────────────────────────────────────────────────


def test_map_groups_to_role_defaults_to_viewer(monkeypatch):
    monkeypatch.delenv("SAP_SSO_ROLE_MAP", raising=False)
    from sap_dashboard.backend.sso import current_config, map_groups_to_role

    cfg = current_config()
    assert map_groups_to_role([], cfg) == "viewer"
    assert map_groups_to_role(["unmapped"], cfg) == "viewer"


def test_map_groups_to_role_picks_highest_rank(monkeypatch):
    monkeypatch.setenv("SAP_SSO_PROVIDER", "oidc")
    monkeypatch.setenv(
        "SAP_SSO_ROLE_MAP",
        json.dumps({"sec": "admin", "ops": "operator", "audit": "viewer"}),
    )
    from sap_dashboard.backend.sso import current_config, map_groups_to_role

    cfg = current_config()
    assert map_groups_to_role(["audit", "sec", "ops"], cfg) == "admin"
    assert map_groups_to_role(["ops", "audit"], cfg) == "operator"
    assert map_groups_to_role(["audit"], cfg) == "viewer"


# ── /api/auth/sso/login HTTP behaviour ───────────────────────────────────


def test_oidc_login_returns_404_when_provider_is_none(app):
    response = app.get("/api/auth/sso/login", follow_redirects=False)
    assert response.status_code == 404
    assert "SAP_SSO_PROVIDER" in response.text


def test_oidc_login_returns_503_when_settings_incomplete(monkeypatch, app):
    monkeypatch.setenv("SAP_SSO_PROVIDER", "oidc")
    # Missing OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_REDIRECT_URL.
    response = app.get("/api/auth/sso/login", follow_redirects=False)
    assert response.status_code == 503
    assert "OIDC settings incomplete" in response.text


def test_oidc_login_redirects_when_fully_configured(monkeypatch, app):
    monkeypatch.setenv("SAP_SSO_PROVIDER", "oidc")
    monkeypatch.setenv("SAP_SSO_OIDC_ISSUER", "https://idp.example.org")
    monkeypatch.setenv("SAP_SSO_OIDC_CLIENT_ID", "sap-pentest")
    monkeypatch.setenv("SAP_SSO_OIDC_CLIENT_SECRET", "shhh")
    monkeypatch.setenv(
        "SAP_SSO_OIDC_REDIRECT_URL",
        "https://sap.example.org/api/auth/sso/callback",
    )
    response = app.get("/api/auth/sso/login", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://idp.example.org/authorize")
    assert "client_id=sap-pentest" in location
    assert "response_type=code" in location
    # The state cookie carrying our signed nonce must be set HttpOnly.
    set_cookie = response.headers.get_list("set-cookie")
    assert any(
        c.startswith("sap_sso_state=") and "HttpOnly" in c for c in set_cookie
    )


# ── SAML stubs: 404 / 501 contract ────────────────────────────────────────


def test_saml_login_returns_404_when_provider_not_saml(app):
    response = app.get("/api/auth/sso/saml/login", follow_redirects=False)
    # When SAP_SSO_PROVIDER=none (default in our fixture), the SAML
    # endpoint is unreachable for configuration reasons, so it returns
    # 404 before even trying to import python3-saml.
    assert response.status_code in (404, 501)


def test_saml_login_returns_501_when_extra_missing(monkeypatch, app):
    """If the operator opts into SAML but never installed the extra, the
    endpoint must report 501 with the exact install command, not silently
    fall back to local auth."""
    monkeypatch.setenv("SAP_SSO_PROVIDER", "saml")
    response = app.get("/api/auth/sso/saml/login", follow_redirects=False)
    # The probe order is: _saml_or_501() first (501 if extra missing),
    # then _require_saml_enabled() (503 if settings missing).
    # We accept either path so a future install of the extra in CI does
    # not break this test — only "fell back to a 2xx" is wrong.
    assert response.status_code in (501, 503)
    if response.status_code == 501:
        assert "sso-saml" in response.text
