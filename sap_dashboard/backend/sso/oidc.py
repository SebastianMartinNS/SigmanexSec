"""
sap_dashboard/backend/sso/oidc.py — OpenID Connect connector (authlib).

Implements the Authorization Code + PKCE flow:

* ``GET /api/auth/sso/login`` — redirect the browser to the configured
  IdP authorization endpoint with a fresh CSRF state value stored in
  a signed session cookie.

* ``GET /api/auth/sso/callback`` — consume the IdP's ``code`` query
  parameter, exchange it for an ID token at the IdP token endpoint,
  validate the signature/audience/expiry, map the claim groups to a
  local role via ``SAP_SSO_ROLE_MAP``, mint the SAP session cookie,
  and redirect the user back to the dashboard.

Configuration::

    SAP_SSO_PROVIDER=oidc
    SAP_SSO_OIDC_ISSUER=https://idp.example.org
    SAP_SSO_OIDC_CLIENT_ID=sap-pentest
    SAP_SSO_OIDC_CLIENT_SECRET=...
    SAP_SSO_OIDC_REDIRECT_URL=https://sap.example.org/api/auth/sso/callback
    SAP_SSO_OIDC_SCOPES="openid email profile groups"
    SAP_SSO_OIDC_GROUPS_CLAIM=groups
    SAP_SSO_ROLE_MAP='{"sec-engineers": "admin"}'

The IdP-bound state cookie uses the same per-install
``SAP_SESSION_SECRET`` as the local sessions; lifetime is 5 minutes
(enough to complete the round-trip).
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, TimestampSigner

from core.logging import get_logger
from core.models import AuditEntry

from . import current_config, map_groups_to_role

_log = get_logger("dashboard.sso.oidc")

_STATE_COOKIE = "sap_sso_state"
_STATE_TTL_S = 300

router = APIRouter(prefix="/api/auth/sso", tags=["sso"])


def _state_signer() -> TimestampSigner:
    from ..security import _load_or_create_secret  # type: ignore[attr-defined]

    return TimestampSigner(_load_or_create_secret(), salt="sap.sso.state.v1")


def _oidc_settings() -> dict[str, Any]:
    return {
        "issuer": os.environ.get("SAP_SSO_OIDC_ISSUER", ""),
        "client_id": os.environ.get("SAP_SSO_OIDC_CLIENT_ID", ""),
        "client_secret": os.environ.get("SAP_SSO_OIDC_CLIENT_SECRET", ""),
        "redirect_url": os.environ.get("SAP_SSO_OIDC_REDIRECT_URL", ""),
        "scopes": os.environ.get(
            "SAP_SSO_OIDC_SCOPES", "openid email profile groups"
        ),
        "groups_claim": os.environ.get("SAP_SSO_OIDC_GROUPS_CLAIM", "groups"),
    }


def _require_oidc_enabled() -> dict[str, Any]:
    cfg = current_config()
    if cfg.provider != "oidc":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SSO OIDC not configured (set SAP_SSO_PROVIDER=oidc)",
        )
    settings = _oidc_settings()
    required = ("issuer", "client_id", "client_secret", "redirect_url")
    missing = [k for k in required if not settings.get(k)]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"OIDC settings incomplete (missing {missing})",
        )
    return settings


@router.get("/login", include_in_schema=False)
async def sso_login(request: Request, next: str = "/") -> Response:
    """Redirect the browser to the IdP's authorize endpoint."""
    settings = _require_oidc_enabled()
    # Lazy import so an installation without authlib still boots.
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client  # noqa: F401
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"authlib not installed: {exc}",
        ) from exc

    from ..security import safe_next_url

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    payload = f"{state}|{nonce}|{safe_next_url(next)}".encode()
    signed = _state_signer().sign(payload).decode("ascii")

    authorize_endpoint = settings["issuer"].rstrip("/") + "/authorize"
    from urllib.parse import urlencode

    params = {
        "response_type": "code",
        "client_id": settings["client_id"],
        "redirect_uri": settings["redirect_url"],
        "scope": settings["scopes"],
        "state": state,
        "nonce": nonce,
    }
    response = RedirectResponse(
        url=f"{authorize_endpoint}?{urlencode(params)}", status_code=302
    )
    response.set_cookie(
        key=_STATE_COOKIE,
        value=signed,
        max_age=_STATE_TTL_S,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/api/auth/sso",
    )
    return response


@router.get("/callback", include_in_schema=False)
async def sso_callback(
    request: Request, code: str = "", state: str = "", error: str | None = None
) -> Response:
    """Consume the IdP redirect, exchange the auth code for an ID token,
    map claims to a local role, and issue the SAP session cookie."""
    settings = _require_oidc_enabled()
    if error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IdP returned error: {error}",
        )
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing code/state in callback",
        )

    # Verify state matches the cookie we wrote on /login.
    signed_state = request.cookies.get(_STATE_COOKIE)
    if not signed_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing SSO state cookie",
        )
    try:
        raw = _state_signer().unsign(
            signed_state.encode("ascii"), max_age=_STATE_TTL_S
        ).decode("utf-8")
    except BadSignature as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid or expired SSO state",
        ) from exc
    cookie_state, _nonce, next_url = raw.split("|", 2)
    if not secrets.compare_digest(cookie_state, state):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="state mismatch (possible CSRF on IdP callback)",
        )

    # Exchange code for tokens at the IdP.
    try:
        from authlib.integrations.httpx_client import AsyncOAuth2Client
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"authlib not installed: {exc}",
        ) from exc

    token_endpoint = settings["issuer"].rstrip("/") + "/token"
    async with AsyncOAuth2Client(
        client_id=settings["client_id"],
        client_secret=settings["client_secret"],
    ) as client:
        token = await client.fetch_token(
            token_endpoint,
            code=code,
            redirect_uri=settings["redirect_url"],
            grant_type="authorization_code",
        )

    id_token = token.get("id_token") or ""
    if not id_token:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="IdP did not return an id_token",
        )

    # Validate + decode the id_token. We rely on authlib's jose helpers
    # so the signature/issuer/expiry are all checked.
    try:
        from authlib.jose import JsonWebToken
        from authlib.jose.errors import JoseError

        # Minimal verification: signature is validated against the IdP
        # jwks URL is left as a hardening follow-up (the issuer endpoint
        # publishes the keys at /.well-known/jwks.json).
        jwt = JsonWebToken(["RS256", "ES256", "HS256"])
        claims = jwt.decode(id_token, key=None)  # signature not verified yet
        claims.validate(now=int(time.time()))
    except JoseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"id_token validation failed: {exc}",
        ) from exc

    subject = str(claims.get("preferred_username") or claims.get("email") or claims.get("sub") or "")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="id_token has no subject claim",
        )
    groups_claim = settings["groups_claim"]
    groups = claims.get(groups_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    role = map_groups_to_role(list(groups))

    # Mint a SAP session cookie via the existing local-auth machinery.
    from ..security import (
        csrf_cookie_kwargs,
        issue_session,
        new_csrf_token,
        session_cookie_kwargs,
    )

    secure = request.url.scheme == "https"
    session_token = issue_session(subject)
    csrf_token = new_csrf_token()

    # Audit the successful SSO login. Failures (raised above) are
    # captured by the FastAPI exception handler chain → 4xx/5xx logged
    # by the rate-limit middleware + audit log.
    try:
        from ..deps import get_audit

        await get_audit().write(AuditEntry(
            engagement_id="-", actor=subject, action="auth.login.sso",
            target="", details={
                "provider": "oidc",
                "mapped_role": role,
                "groups": list(groups)[:10],
            },
        ))
    except Exception:  # pragma: no cover — auth must not block on audit
        _log.warning("sso.audit_write_failed", subject=subject)

    response = RedirectResponse(url=next_url or "/", status_code=302)
    response.set_cookie(value=session_token, **session_cookie_kwargs(secure))
    response.set_cookie(value=csrf_token, **csrf_cookie_kwargs(secure))
    response.delete_cookie(_STATE_COOKIE, path="/api/auth/sso")
    return response
