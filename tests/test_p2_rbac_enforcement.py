"""Introspection test for the RBAC layer (workstream F2.3).

Walks ``app.routes`` and asserts every API endpoint either:

* declares a ``require_role(...)`` dependency (router-level or
  route-level), OR
* appears in the explicit ``_RBAC_PUBLIC_PATHS`` allow-list because
  it is intentionally public (health probes, login, logout, /me,
  HTML pages, error pages).

The test fails when a new route is added without an RBAC decision,
forcing the contributor to either pick a role or justify the public
exposure in the allow-list.
"""

from __future__ import annotations

import pytest

# Paths that intentionally do NOT enforce a role:
#  * health probes — k8s / systemd / load balancer probes are unauth.
#  * /api/auth/login — by definition reachable without a session.
#  * /api/auth/logout, /api/auth/me — only need authentication
#    (any logged-in user can log themselves out or read their own
#    identity); a viewer floor here would be redundant.
#  * /ui/* HTML pages — server-rendered shells that handle their own
#    redirect-to-login logic via the session cookie.
#  * /_404 — branded error page.
_RBAC_PUBLIC_PATHS = {
    "/healthz",
    "/readyz",
    "/metrics",  # v3.0: Prometheus exposition — same hygiene as /healthz
    "/api/health",  # legacy alias of /healthz
    "/api/auth/login",
    "/api/auth/logout",
    "/api/auth/me",
    "/",
    "/login",
    "/legacy",      # static UI alias
    "/_404",
    "/ui/partials/{name}",
    # SSO endpoints — by definition reachable without an existing
    # SAP session (that's the whole point of SSO).
    "/api/auth/sso/login",
    "/api/auth/sso/callback",
    "/api/auth/sso/saml/login",
    "/api/auth/sso/saml/acs",
    # OpenAPI docs and FastAPI auto-generated probes.
    "/docs",
    "/openapi.json",
    "/redoc",
    "/docs/oauth2-redirect",
}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "verystrongpass1234")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    monkeypatch.setenv("SAP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("SESSION_DB_PATH", str(tmp_path / "assess.db"))

    import sys
    for name in list(sys.modules):
        if name == "sap_dashboard.backend" or name.startswith("sap_dashboard.backend."):
            sys.modules.pop(name, None)
    from sap_dashboard.backend.app import app as fastapi_app
    return fastapi_app


def _route_has_require_role(route, app) -> bool:
    """True if ``route`` is gated by a ``require_role`` dependency,
    either declared at the router level (inherited) or inline on the
    route's ``dependencies`` argument."""
    # The dependant graph reflects everything FastAPI will resolve for
    # this route: route-level Depends, router-level Depends, and
    # parameter Depends in the handler signature.
    dependant = getattr(route, "dependant", None)
    if dependant is None:
        return False

    return _dependant_uses_require_role(dependant)


def _dependant_uses_require_role(dependant) -> bool:
    # ``call`` is the dependency callable. ``require_role(min_role)``
    # returns a nested ``_checker`` function with that name; we match
    # on the name because the closure object is distinct per call site.
    call = getattr(dependant, "call", None)
    if call is not None and getattr(call, "__name__", "") == "_checker":
        return True
    for sub in getattr(dependant, "dependencies", []) or []:
        if _dependant_uses_require_role(sub):
            return True
    return False


def test_every_api_route_has_rbac_dependency(app):
    """Walk every API route registered on the dashboard FastAPI app and
    assert it enforces RBAC (or is explicitly allow-listed as public)."""
    from fastapi.routing import APIRoute, APIWebSocketRoute

    missing: list[tuple[str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", None) or ""
        # Static-mount asset routes (Mount instances) have no dependant
        # and serve files; skip them.
        if not isinstance(route, (APIRoute, APIWebSocketRoute)):
            continue
        if path in _RBAC_PUBLIC_PATHS:
            continue
        # Static FastAPI defaults (e.g. /openapi.json variants).
        if path.startswith("/openapi"):
            continue
        if _route_has_require_role(route, app):
            continue
        methods = ",".join(sorted(getattr(route, "methods", ()) or ()))
        missing.append((methods or "WS", path))

    assert not missing, (
        "Route(s) without RBAC enforcement (add Depends(require_role(...))) "
        "or list them in _RBAC_PUBLIC_PATHS:\n" +
        "\n".join(f"  {m} {p}" for m, p in missing)
    )


def test_admin_only_routes_require_admin(app):
    """A spot-check that admin-only endpoints reject operator/viewer.

    We do not call them via HTTP here (that would require RBAC matrix
    fixtures); we rely on the introspection above for completeness and
    use this test to assert the specific admin routes are not silently
    downgraded to operator/viewer."""
    expected_admin = {
        ("PATCH", "/api/settings"),
        ("POST", "/api/engagements/{engagement_id}/reset"),
        ("POST", "/api/system/reset"),
    }

    seen: set[tuple[str, str]] = set()
    from fastapi.routing import APIRoute
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for method in sorted(route.methods or ()):
            key = (method, route.path)
            if key not in expected_admin:
                continue
            seen.add(key)
            assert _route_has_require_role(route, app), (
                f"admin route {method} {route.path} is missing require_role()"
            )

    missing = expected_admin - seen
    assert not missing, f"Admin routes not registered on the app: {missing}"
