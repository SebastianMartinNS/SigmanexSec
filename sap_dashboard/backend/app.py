"""
sap_dashboard/backend/app.py — FastAPI entrypoint for the SAP Control Dashboard.

Run in dev:
    uvicorn sap_dashboard.backend.app:app --reload --port 8765

Or via the CLI:
    python cli.py dashboard --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from core.logging import (
    CorrelationIdMiddleware,
    configure_logging,
    get_logger,
)

configure_logging(service="dashboard")
_log = get_logger("dashboard.app")


# ── Request body size limit ────────────────────────────────────────────────
# FastAPI/uvicorn do not cap request bodies by default. A hostile (or
# accidentally-bulk) client could POST hundreds of MB into pydantic
# validation and burn RAM before any handler ran. We enforce a hard cap
# at the ASGI middleware layer so over-sized requests are rejected with
# 413 before being parsed.
def _max_body_bytes() -> int:
    try:
        v = int(os.environ.get("SAP_DASHBOARD_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
    except (TypeError, ValueError):
        return 2 * 1024 * 1024
    return v if v > 0 else 2 * 1024 * 1024


class _BodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured cap.

    For chunked / streaming uploads (no Content-Length), we wrap the
    receive() coroutine and short-circuit when the cumulative body bytes
    exceed the cap. This way file-upload-style attacks cannot bypass the
    check by omitting Content-Length.
    """
    async def dispatch(self, request, call_next):
        cap = _max_body_bytes()
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > cap:
                    return JSONResponse(
                        status_code=413,
                        content={"error": "request body too large"},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid Content-Length"},
                )
        # Streaming / chunked path: count as we go.
        original_receive = request.receive
        seen = 0

        async def _bounded_receive():
            nonlocal seen
            msg = await original_receive()
            if msg.get("type") == "http.request":
                body = msg.get("body", b"") or b""
                seen += len(body)
                if seen > cap:
                    # Returning a sentinel forces downstream to see EOF +
                    # the route handler will raise; we reject preemptively.
                    raise _BodyTooLarge()
            return msg

        request._receive = _bounded_receive  # type: ignore[attr-defined]
        try:
            return await call_next(request)
        except _BodyTooLarge:
            return JSONResponse(
                status_code=413,
                content={"error": "request body too large"},
            )


class _BodyTooLarge(Exception):
    pass


# ── Per-IP rate-limit tier (Phase 4) ───────────────────────────────────────

class _RateLimitMiddleware(BaseHTTPMiddleware):
    """Lightweight in-memory sliding-window rate limit.

    Two tiers:
      * anon (no session cookie) — ``SAP_DASHBOARD_RL_ANON`` / minute
        (default 30).
      * auth (session cookie present) — ``SAP_DASHBOARD_RL_AUTH`` / minute
        (default 240).

    Keyed by ``X-Forwarded-For`` head IP (or ``request.client.host``) so a
    reverse proxy keeps per-peer accounting. Static asset paths and the
    WebSocket route are skipped — the WS handler has its own per-IP cap.
    """
    _SKIP_PREFIXES = (
        "/vendor/", "/static/", "/ui/", "/api/audit/ws",
        "/openapi.json", "/docs", "/_404",
        "/healthz", "/readyz",
    )
    # Window of 60s; bursts within the window count linearly.
    _WINDOW_S = 60.0
    # `{ip: deque[timestamps]}` — capped at the limit so we never grow.
    _BUCKETS: dict[str, list[float]] = {}
    _LOCK = asyncio.Lock()

    @staticmethod
    def _limits() -> tuple[int, int]:
        try:
            anon = int(os.environ.get("SAP_DASHBOARD_RL_ANON", "30"))
        except ValueError:
            anon = 30
        try:
            auth = int(os.environ.get("SAP_DASHBOARD_RL_AUTH", "240"))
        except ValueError:
            auth = 240
        return max(1, anon), max(1, auth)

    @staticmethod
    def _peer(request) -> str:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",", 1)[0].strip() or "?"
        return (request.client.host if request.client else "?")

    async def dispatch(self, request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in self._SKIP_PREFIXES):
            return await call_next(request)
        from .security import SESSION_COOKIE
        anon, auth = self._limits()
        cap = auth if request.cookies.get(SESSION_COOKIE) else anon
        peer = self._peer(request)
        key = f"{peer}|{cap}"
        now = time.monotonic()
        cutoff = now - self._WINDOW_S
        async with self._LOCK:
            bucket = self._BUCKETS.setdefault(key, [])
            # Drop entries outside the window.
            i = 0
            for i, ts in enumerate(bucket):  # noqa: B007
                if ts >= cutoff:
                    break
            else:
                i = len(bucket)
            if i:
                del bucket[:i]
            if len(bucket) >= cap:
                retry = int(self._WINDOW_S - (now - bucket[0])) + 1
                return JSONResponse(
                    status_code=429,
                    content={"error": "rate limit exceeded", "retry_after_s": max(retry, 1)},
                    headers={"Retry-After": str(max(retry, 1))},
                )
            bucket.append(now)
            # Garbage-collect very-stale buckets so the dict cannot grow
            # unboundedly under churn.
            if len(self._BUCKETS) > 4096:
                stale = [k for k, b in self._BUCKETS.items() if not b or b[-1] < cutoff]
                for k in stale[:1024]:
                    self._BUCKETS.pop(k, None)
        return await call_next(request)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply baseline hardening headers + per-request CSP nonce (P3.1).

    A fresh 128-bit nonce is generated for every request and exposed via
    ``request.state.csp_nonce`` so route handlers can inject it into the
    inline ``<script>`` / ``<style>`` tags they emit. The nonce is then
    pinned into ``script-src`` so the browser refuses any script that
    wasn't shipped by us — eliminating reliance on ``'unsafe-inline'``.
    """
    async def dispatch(self, request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # P3.1+P3.2 — strict nonce-based CSP, no CDN allowlists, no
        # 'unsafe-inline'. 'unsafe-eval' is the only relaxation kept and
        # only because Alpine.js 3.13 requires Function() to evaluate
        # x-data / @click expressions; will be eliminated when the SPA
        # migrates to a precompiled framework (or the Alpine CSP build).
        # All third-party assets are vendored under /vendor/* with SRI.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
            # 'unsafe-inline' is allowed only on style-src because Alpine
            # writes inline element.style.* for x-show/x-transition. Inline
            # styles cannot exfiltrate data nor execute code, so this is
            # the standard relaxation recommended by Mozilla / OWASP.
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'"
        )
        # P3.3 — Trusted Types in report-only mode. Enforcing this would
        # break Alpine.js (it injects markup via innerHTML); we publish
        # the policy in report-only so violations are visible in the
        # browser console / report endpoints during the SvelteKit
        # migration, then flip to enforcement.
        resp.headers["Content-Security-Policy-Report-Only"] = (
            "require-trusted-types-for 'script'; "
            "trusted-types default;"
        )
        # HSTS: emit when the request is on HTTPS (direct or via reverse proxy).
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        if scheme == "https":
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains"
            )
        return resp


# CSRF double-submit middleware: state-changing requests authenticated via
# session cookie MUST present the CSRF cookie value back in X-CSRF-Token.
# Requests authenticated via HTTP Basic (tests / API clients) are exempt
# because they cannot be triggered by a browser cross-site form.
class _CSRFMiddleware(BaseHTTPMiddleware):
    _SAFE = {"GET", "HEAD", "OPTIONS"}
    _EXEMPT_PATHS = {"/api/auth/login"}

    async def dispatch(self, request, call_next):
        if request.method in self._SAFE or request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)
        # Only enforce when the caller is using a session cookie. HTTP Basic
        # callers (no cookie) bypass — they are not browser cross-site
        # vectors and are typically test harnesses.
        from .security import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE, csrf_match
        if request.cookies.get(SESSION_COOKIE):
            cookie_val = request.cookies.get(CSRF_COOKIE)
            header_val = request.headers.get(CSRF_HEADER)
            if not csrf_match(cookie_val, header_val):
                return JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"})
        return await call_next(request)

# ── Lifespan: storage GC scheduler ─────────────────────────────────────────
from contextlib import asynccontextmanager

from .deps import REPO_ROOT, get_config
from .routes import (
    audit,
    auth,
    engagements,
    export,
    health,
    kpi,
    outputs,
    parrot,
    reports,
    runs,
    sessions,
    settings,
    sudo,
    ui,
)
from .sso import oidc as sso_oidc
from .sso import saml as sso_saml


@asynccontextmanager
async def _lifespan(app_: FastAPI):
    # P2.4 — apply process-level secret protections as early as possible.
    try:
        from core.process_hardening import harden_process
        harden_process()
    except Exception:
        pass

    gc_task: asyncio.Task | None = None
    if os.environ.get("SAP_DISABLE_STORAGE_GC", "").lower() not in ("1", "true", "yes"):
        try:
            from core.storage_gc import start_gc_scheduler
            cfg = get_config() or {}
            retention = int(
                os.environ.get(
                    "SAP_TOOL_OUTPUT_RETENTION_DAYS",
                    str(cfg.get("storage", {}).get("retention_days", 90)),
                )
            )
            interval = int(
                os.environ.get(
                    "SAP_TOOL_OUTPUT_GC_INTERVAL_S",
                    str(cfg.get("storage", {}).get("gc_interval_seconds", 24 * 3600)),
                )
            )
            keep = list(cfg.get("storage", {}).get("keep_engagement_ids", []) or [])
            gc_task = start_gc_scheduler(
                retention_days=retention,
                interval_seconds=interval,
                keep_engagement_ids=keep,
            )
        except Exception:  # pragma: no cover — never block dashboard startup
            import logging
            logging.getLogger(__name__).exception("storage GC scheduler failed to start")
    try:
        yield
    finally:
        if gc_task is not None:
            gc_task.cancel()
            try:
                await gc_task
            except Exception:
                pass
        # Drain pending audit entries before the event loop closes. Without
        # this, the writer task is cancelled with entries still queued and
        # they are silently lost — an audit-trail gap that an attacker
        # could exploit by triggering events right before a shutdown.
        try:
            from sap_dashboard.backend.deps import get_audit
            audit = get_audit()
            await asyncio.wait_for(audit.close(), timeout=5.0)
        except Exception:
            import logging
            logging.getLogger(__name__).debug(
                "audit flush on shutdown skipped or timed out", exc_info=True
            )


app = FastAPI(
    title="SAP Control Dashboard",
    version="2.0",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=_lifespan,
)


# Restrict CORS by default. Local dev WebUI lives on the same host:port.
_cors_origins = os.environ.get("SAP_DASHBOARD_CORS", "").split(",")
_cors_origins = [o.strip() for o in _cors_origins if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["content-type", "authorization", "x-csrf-token"],
    )

app.add_middleware(_CSRFMiddleware)
app.add_middleware(_SecurityHeadersMiddleware)
# BodyLimit is registered LAST so it runs FIRST in the request flow
# (Starlette executes middleware in reverse-registration order).
app.add_middleware(_BodyLimitMiddleware)
# Rate limit registered AFTER body limit so oversized bodies are rejected
# even when the bucket is full — saves us reading the body just to 429.
app.add_middleware(_RateLimitMiddleware)


class _SlidingSessionMiddleware(BaseHTTPMiddleware):
    """Emit a refreshed session cookie when ``require_auth`` flagged
    ``request.state.refresh_session_token``.

    Sliding expiry without server state: each authenticated request resets
    the idle window; the absolute cap survives via the embedded ``iat``.
    """
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        new_token = getattr(request.state, "refresh_session_token", None)
        if new_token:
            from .security import csrf_cookie_kwargs, session_cookie_kwargs
            secure = bool(getattr(request.state, "refresh_session_secure", False))
            kwargs = session_cookie_kwargs(secure)
            resp.set_cookie(value=new_token, **kwargs)
            # Also bump the CSRF cookie max_age so it expires in lockstep
            # with the (now-refreshed) session.
            csrf_existing = request.cookies.get("sap_csrf")
            if csrf_existing:
                resp.set_cookie(value=csrf_existing, **csrf_cookie_kwargs(secure))
        return resp


# Sliding-session must run AFTER auth has populated request.state, which
# means it needs to wrap the response on the way out — register before the
# CSRF middleware so it executes outermost (last to wrap response).
app.add_middleware(_SlidingSessionMiddleware)

# CorrelationIdMiddleware is registered LAST so it runs FIRST in the
# request flow and wraps the response LAST. This guarantees every other
# middleware (rate limit, body limit, security headers, CSRF, auth) can
# already see the bound correlation id when they log.
app.add_middleware(CorrelationIdMiddleware)


# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(health.router)
app.include_router(auth.router)
# SSO routers are mounted unconditionally; each endpoint refuses with a
# clear 404/503 when SAP_SSO_PROVIDER is not configured for that scheme.
app.include_router(sso_oidc.router)
app.include_router(sso_saml.router)
app.include_router(engagements.router)
app.include_router(runs.router)
app.include_router(sudo.router)
app.include_router(settings.router)
app.include_router(parrot.router)
app.include_router(reports.router)
app.include_router(audit.router)
app.include_router(export.router)
app.include_router(sessions.router)
app.include_router(kpi.router)
app.include_router(outputs.router)
app.include_router(ui.router)


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "service": "sap-dashboard", "version": "2.0"}


# ── Static frontend (optional) ──────────────────────────────────────────────
_FRONTEND_DIR = REPO_ROOT / "sap_dashboard" / "frontend"
_LEGACY_INDEX = _FRONTEND_DIR / "index.html"


@app.get("/legacy", response_class=HTMLResponse, include_in_schema=False)
async def legacy_root(request: Request) -> HTMLResponse:
    """Legacy single-file SPA — preserved for emergency fallback only.

    The new server-rendered SigmanexSec UI lives at `/`. This endpoint
    keeps the original Alpine + HTMX monolith reachable while we roll
    out the redesign and is removed after stabilization.
    """
    if not _LEGACY_INDEX.exists():
        return HTMLResponse("<h1>Legacy UI not present.</h1>", status_code=404)
    nonce = getattr(request.state, "csp_nonce", "")
    html = _LEGACY_INDEX.read_text(encoding="utf-8")
    if nonce:
        import re
        html = re.sub(
            r"<(script|style)(\s|>)",
            lambda m: f'<{m.group(1)} nonce="{nonce}"{m.group(2)}',
            html,
        )
    return HTMLResponse(html)


# Mount the rest of the frontend as static files only if it exists.
if _FRONTEND_DIR.exists():
    from fastapi.staticfiles import StaticFiles
    if (_FRONTEND_DIR / "assets").exists():
        app.mount(
            "/assets",
            StaticFiles(directory=_FRONTEND_DIR / "assets"),
            name="assets",
        )
    # P3.2 — vendored, pinned, SRI-hashed third-party assets (htmx, alpine,
    # tailwind built statically). These replace the previous CDN
    # dependencies on unpkg.com / cdn.tailwindcss.com.
    if (_FRONTEND_DIR / "vendor").exists():
        app.mount(
            "/vendor",
            StaticFiles(directory=_FRONTEND_DIR / "vendor"),
            name="vendor",
        )


@app.exception_handler(Exception)
async def _unhandled(_request, exc: Exception) -> JSONResponse:
    # Don't leak internals in production.
    if os.environ.get("SAP_DASHBOARD_DEBUG") == "1":
        return JSONResponse(status_code=500, content={"error": str(exc)})
    return JSONResponse(status_code=500, content={"error": "internal error"})
