"""
sap_dashboard/backend/security.py — Session cookie & CSRF helpers.

P0 hardening: replaces frontend localStorage HTTP Basic with HttpOnly cookies
+ double-submit CSRF token. Server-side state-less, signed via itsdangerous
TimestampSigner with a per-install secret persisted in
$XDG_STATE_HOME/sap/session.key (0600).

Backwards compatible: the existing HTTP Basic path in deps.require_auth is
preserved for tests / CLI clients.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from pathlib import Path

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner

# ── Cookie names & TTL ──────────────────────────────────────────────────────

SESSION_COOKIE = "sap_session"
CSRF_COOKIE    = "sap_csrf"
CSRF_HEADER    = "X-CSRF-Token"

# Sliding-expiry policy:
#   * SESSION_IDLE_S      — max gap between authenticated requests (default 30 min).
#   * SESSION_MAX_AGE_S   — absolute lifetime since first issue (default 8 h).
# The signed cookie payload is ``"<username>|<iat_epoch>"``. The signature
# timestamp is refreshed (sliding) on every authenticated request so the
# cookie expires after SESSION_IDLE_S of inactivity, but the embedded ``iat``
# enforces the absolute cap.
SESSION_IDLE_S    = int(os.environ.get("SAP_SESSION_IDLE", "1800"))
SESSION_MAX_AGE_S = int(os.environ.get("SAP_SESSION_MAX_AGE", "28800"))


# ── Secret material persistence ─────────────────────────────────────────────

def _state_dir() -> Path:
    base = os.environ.get("SAP_STATE_DIR")
    if base:
        return Path(base)
    xdg = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(xdg) / "sap"


def _load_or_create_secret() -> bytes:
    """Per-install signing key. 32 random bytes, persisted with mode 0600."""
    env = os.environ.get("SAP_SESSION_SECRET")
    if env:
        return env.encode()
    p = _state_dir() / "session.key"
    if p.exists():
        try:
            data = p.read_bytes().strip()
            if len(data) >= 32:
                return data
        except OSError:
            pass
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    secret = secrets.token_urlsafe(48).encode()
    # umask-safe write
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    return secret


_SIGNER: TimestampSigner | None = None


def _signer() -> TimestampSigner:
    global _SIGNER
    if _SIGNER is None:
        _SIGNER = TimestampSigner(_load_or_create_secret(), salt="sap.session.v1")
    return _SIGNER


# ── Session token ───────────────────────────────────────────────────────────

def issue_session(username: str, iat: int | None = None) -> str:
    """Returns a signed timestamped token containing username + issued-at.

    ``iat`` is the absolute lifetime anchor; pass an existing value when
    refreshing a sliding-expiry cookie so the absolute cap is preserved.
    """
    if iat is None:
        iat = int(time.time())
    raw = f"{username}|{iat}".encode()
    return _signer().sign(raw).decode("ascii")


def _decode_session(token: str) -> tuple[str, int] | None:
    """Verify signature/idle cap and decode payload to (username, iat).

    Returns ``None`` for invalid/expired/malformed tokens. The signature
    timestamp enforces the idle cap (``SESSION_IDLE_S``). The absolute cap
    is enforced separately by the caller using ``iat``.
    """
    if not token:
        return None
    try:
        raw = _signer().unsign(token.encode("ascii"), max_age=SESSION_IDLE_S)
    except (BadSignature, SignatureExpired):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Backwards compat: legacy tokens (no ``|iat``) are treated as freshly
    # issued so the absolute-age check downgrades to the idle check.
    if "|" in decoded:
        username, iat_s = decoded.rsplit("|", 1)
        try:
            iat = int(iat_s)
        except ValueError:
            return None
    else:
        username, iat = decoded, int(time.time())
    return username, iat


def verify_session(token: str) -> str | None:
    """Returns the username if the token is valid, idle- and absolute-age
    bounded, else None.
    """
    decoded = _decode_session(token)
    if decoded is None:
        return None
    username, iat = decoded
    now = int(time.time())
    if now - iat > SESSION_MAX_AGE_S:
        return None
    return username


def refresh_session(token: str) -> str | None:
    """Issue a fresh signed cookie value preserving the original ``iat``.

    Returns ``None`` if the input is invalid/expired/over the absolute cap;
    in that case the caller MUST clear the cookie and re-prompt for login.
    """
    decoded = _decode_session(token)
    if decoded is None:
        return None
    username, iat = decoded
    now = int(time.time())
    if now - iat > SESSION_MAX_AGE_S:
        return None
    return issue_session(username, iat=iat)


# ── CSRF token (double-submit cookie) ───────────────────────────────────────

def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_match(cookie_value: str | None, header_value: str | None) -> bool:
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(cookie_value, header_value)


# ── Cookie kwargs (centralised so tests can inspect) ────────────────────────

def session_cookie_kwargs(secure: bool) -> dict:
    return {
        "key": SESSION_COOKIE,
        # Browser cookie expiry is the idle window; absolute cap is enforced
        # server-side by ``verify_session`` via the embedded ``iat``.
        "max_age": SESSION_IDLE_S,
        "httponly": True,
        "secure": secure,
        "samesite": "strict",
        "path": "/",
    }


def csrf_cookie_kwargs(secure: bool) -> dict:
    # Readable by JS (double-submit pattern), still SameSite=strict.
    return {
        "key": CSRF_COOKIE,
        "max_age": SESSION_IDLE_S,
        "httponly": False,
        "secure": secure,
        "samesite": "strict",
        "path": "/",
    }


# ── Open-redirect guard ─────────────────────────────────────────────────────

def safe_next_url(value: str | None, fallback: str = "/") -> str:
    """Return ``value`` if it is a safe same-origin path, else ``fallback``.

    Blocks all schemes (``javascript:``, ``data:``, ``vbscript:``, ...),
    protocol-relative URLs (``//evil``, ``///evil``), backslash tricks
    (``\\\\evil``), embedded CR/LF/NUL, and anything that does not start
    with a single ``/``.
    """
    if not value or not isinstance(value, str):
        return fallback
    # Reject control characters that smuggle headers/scheme.
    if any(ch in value for ch in ("\r", "\n", "\x00", "\t", " ", "\\")):
        return fallback
    if not value.startswith("/"):
        return fallback
    # Protocol-relative — //host, ///host, etc.
    if value.startswith("//"):
        return fallback
    # Reject scheme-only forms that some browsers normalise.
    lowered = value.lower().lstrip()
    for bad in ("javascript:", "data:", "vbscript:", "file:"):
        if bad in lowered:
            return fallback
    return value


# ── CSRF rotation helper ────────────────────────────────────────────────────

def rotate_csrf(request, response) -> str:
    """Issue a fresh CSRF token cookie on ``response`` and return it.

    Call after privileged mutations (sudo unlock/lock, export,
    credential changes) so a stolen-and-replayed token cannot be reused.
    The session cookie is NOT rotated — the user keeps their session.
    """
    secure = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )
    new_tok = new_csrf_token()
    response.set_cookie(value=new_tok, **csrf_cookie_kwargs(secure))
    return new_tok
