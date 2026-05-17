"""
sap_dashboard/backend/routes/ui.py — Server-rendered HTML pages (Jinja2).

Serves the SigmanexSec branded dashboard:
  - GET /            → if authenticated, render dashboard shell; else redirect /login
  - GET /login       → render full-screen login page (public; if already
                       authenticated, redirect to next/?)
  - GET /ui/partials/{name} → HTMX partial fragments (auth required)

The CSP nonce produced by the SecurityHeadersMiddleware is injected into
every template as {{ csp_nonce }} so all inline <script>/<style> blocks
(theme bootstrap, JSON state pre-render) can be allow-listed without
relaxing the policy. No CDN requests.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..deps import REPO_ROOT, get_config, require_auth
from ..rbac import lookup_role
from ..security import SESSION_COOKIE, safe_next_url, verify_session

_TEMPLATES_DIR = REPO_ROOT / "sap_dashboard" / "frontend" / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


router = APIRouter(tags=["ui"])


def _current_user(request: Request) -> str | None:
    """Return the username from a valid session cookie, else None.

    Mirrors the cookie branch of `require_auth` but never raises — used
    by HTML routes that need to decide between rendering and redirecting.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user = verify_session(token)
    if not user:
        return None
    # Make sure the user still exists in the auth directory (avoid stale
    # cookies after a creds rotation).
    from ..deps import _expected_creds
    expected = _expected_creds()
    if expected is None:
        return None
    if user == expected[0] or lookup_role(user) is not None:
        return user
    return None


def _ctx(request: Request, **extra) -> dict:
    """Common template context (nonce, brand, version, current user)."""
    cfg = get_config() or {}
    user = _current_user(request)
    role = lookup_role(user) if user else None
    return {
        "request": request,
        "csp_nonce": getattr(request.state, "csp_nonce", ""),
        "brand": {
            "name": "SigmanexSec",
            "tagline": "Security Assessment Platform",
            "version": "2.0",
        },
        "user": user,
        "role": role or ("viewer" if user else None),
        "config": cfg,
        **extra,
    }


# ── Pages ───────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def page_root(request: Request) -> HTMLResponse:
    user = _current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return templates.TemplateResponse("dashboard.html", _ctx(request))


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def page_login(request: Request, next: str = "/") -> HTMLResponse:
    user = _current_user(request)
    target = safe_next_url(next, fallback="/")
    if user:
        return RedirectResponse(url=target, status_code=302)
    return templates.TemplateResponse(
        "login.html",
        _ctx(request, next_url=target),
    )


# ── HTMX partials (authenticated) ──────────────────────────────────────────

_PARTIALS = {
    "overview", "engagements", "console", "audit",
    "vault", "tools", "sessions", "settings", "reports",
}


@router.get("/ui/partials/{name}", response_class=HTMLResponse, include_in_schema=False)
async def page_partial(name: str, request: Request, _user: str = Depends(require_auth)) -> HTMLResponse:
    if name not in _PARTIALS:
        raise HTTPException(status_code=404, detail="unknown partial")
    return templates.TemplateResponse(f"partials/{name}.html", _ctx(request, view=name))


# ── Branded error pages ────────────────────────────────────────────────────

@router.get("/_404", response_class=HTMLResponse, include_in_schema=False)
async def page_404(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("error.html", _ctx(request, code=404, title="Pagina non trovata", message="La risorsa richiesta non esiste."))
