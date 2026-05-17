"""
sap_dashboard/backend/sso — Optional Single Sign-On connectors.

Two providers are supported:

* **OIDC** (`oidc.py`) — shipped in the base image (``authlib`` is a
  core dependency). Tested in CI against the Dex mock IdP container.

* **SAML 2.0** (`saml.py`) — opt-in via the ``[sso-saml]`` extra
  (``pip install sap-pentest[sso-saml]``); requires libxml2 +
  libxmlsec1 native libraries on the host. The module imports
  ``python3-saml`` lazily so the dashboard boots without SAML deps.

Provider selection is driven by ``SAP_SSO_PROVIDER`` (``none`` /
``oidc`` / ``saml``). When set to ``none`` (the default) the SSO router
is still mounted but every endpoint returns HTTP 404; the legacy local
auth (``SAP_DASHBOARD_USER`` + ``SAP_DASHBOARD_USERS``) keeps working.

Group → role mapping is configured via ``SAP_SSO_ROLE_MAP``: a JSON
object that maps an IdP claim value to one of ``viewer`` / ``operator``
/ ``admin``. Example::

    SAP_SSO_ROLE_MAP='{"sec-engineers": "admin", "auditors": "viewer"}'

When a user authenticates via SSO and at least one of their group
claims appears in the map, the highest-ranking matching role wins.
If no map entry matches, the user defaults to ``viewer`` so a
misconfiguration cannot accidentally grant privileged access.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Literal

ProviderKind = Literal["none", "oidc", "saml"]


@dataclass(frozen=True)
class SsoConfig:
    provider: ProviderKind
    role_map: dict[str, str]

    @property
    def enabled(self) -> bool:
        return self.provider in ("oidc", "saml")


def current_config() -> SsoConfig:
    raw = (os.environ.get("SAP_SSO_PROVIDER") or "none").strip().lower()
    if raw not in ("oidc", "saml", "none"):
        raw = "none"
    try:
        role_map_raw = os.environ.get("SAP_SSO_ROLE_MAP") or "{}"
        role_map = json.loads(role_map_raw)
        if not isinstance(role_map, dict):
            role_map = {}
    except json.JSONDecodeError:
        role_map = {}
    # Normalise role values; refuse unknown roles silently.
    valid_roles = {"viewer", "operator", "admin"}
    cleaned = {
        str(k): str(v).lower()
        for k, v in role_map.items()
        if str(v).lower() in valid_roles
    }
    return SsoConfig(provider=raw, role_map=cleaned)  # type: ignore[arg-type]


def map_groups_to_role(groups: list[str], cfg: SsoConfig | None = None) -> str:
    """Return the highest-rank role that matches any of *groups* via
    cfg.role_map. Defaults to ``viewer`` so a missing mapping never
    accidentally grants privilege."""
    if cfg is None:
        cfg = current_config()
    if not groups:
        return "viewer"
    rank = {"viewer": 0, "operator": 1, "admin": 2}
    best = "viewer"
    for g in groups:
        role = cfg.role_map.get(g)
        if role and rank.get(role, 0) > rank[best]:
            best = role
    return best
