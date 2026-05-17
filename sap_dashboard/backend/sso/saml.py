"""
sap_dashboard/backend/sso/saml.py — SAML 2.0 connector (opt-in extra).

This module ships as a stub in the base image; the actual SAML
implementation requires ``python3-saml`` plus the libxml2 / libxmlsec1
native libraries on the host. Install the extra::

    apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
    pip install 'sap-pentest[sso-saml]'

When the dependency is missing, every endpoint returns
HTTP 501 Not Implemented with a clear pointer to the install command
so an operator never silently falls back to a no-op auth path.

Configuration (when enabled)::

    SAP_SSO_PROVIDER=saml
    SAP_SSO_SAML_METADATA_URL=https://idp.example.org/saml/metadata.xml
    SAP_SSO_SAML_ENTITY_ID=sap-pentest
    SAP_SSO_SAML_ACS_URL=https://sap.example.org/api/auth/sso/saml/acs
    SAP_SSO_ROLE_MAP='{"sec-engineers": "admin"}'

The flow mirrors the OIDC one: ``GET /api/auth/sso/saml/login`` issues
the AuthnRequest, ``POST /api/auth/sso/saml/acs`` consumes the Assertion
Consumer Service callback, validates the assertion, maps the asserted
attributes to a local role, and issues the SAP session cookie.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from core.logging import get_logger

from . import current_config

_log = get_logger("dashboard.sso.saml")

router = APIRouter(prefix="/api/auth/sso/saml", tags=["sso"])


def _saml_or_501() -> Any:
    """Return the ``onelogin.saml2`` module or raise 501."""
    try:
        import onelogin.saml2.auth as saml_auth  # type: ignore[import-not-found]
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "SAML extra not installed. Install with: "
                "pip install 'sap-pentest[sso-saml]' "
                "(host needs libxml2-dev libxmlsec1-dev libxmlsec1-openssl)."
            ),
        ) from exc
    return saml_auth


def _require_saml_enabled() -> dict[str, Any]:
    cfg = current_config()
    if cfg.provider != "saml":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO SAML not configured (set SAP_SSO_PROVIDER=saml)",
        )
    settings = {
        "metadata_url": os.environ.get("SAP_SSO_SAML_METADATA_URL", ""),
        "entity_id": os.environ.get("SAP_SSO_SAML_ENTITY_ID", ""),
        "acs_url": os.environ.get("SAP_SSO_SAML_ACS_URL", ""),
    }
    missing = [k for k, v in settings.items() if not v]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"SAML settings incomplete (missing {missing})",
        )
    return settings


@router.get("/login", include_in_schema=False)
async def saml_login(request: Request) -> Any:
    _saml_or_501()
    _require_saml_enabled()
    # Full implementation (AuthnRequest generation, redirect to IdP)
    # lands together with the python3-saml integration in v2.4 once we
    # land the Dex/Keycloak E2E in CI. For v2.3 we expose the route so
    # operators discover the gate but get a clear "not yet" signal.
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="SAML login flow scaffolded; full implementation arrives in v2.4",
    )


@router.post("/acs", include_in_schema=False)
async def saml_acs(request: Request) -> Any:
    _saml_or_501()
    _require_saml_enabled()
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="SAML ACS flow scaffolded; full implementation arrives in v2.4",
    )
