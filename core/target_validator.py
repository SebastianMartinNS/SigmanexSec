"""
core/target_validator.py — Defensive target normalization.

scope_validator.py answers "is this target authorized?". This module
answers the orthogonal question "is this string even a *valid* target?"
and applies safety filters that should hold regardless of scope (e.g.
an engagement scope that mistakenly includes 127.0.0.0/8 should still
reject loopback unless explicitly opted-in).

Returns a normalized form (lowercased, IDNA-encoded for IDNs, IP
networks collapsed) so that downstream scope checks compare
apples-to-apples.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import idna


class InvalidTarget(ValueError):
    """Raised when a target string cannot be parsed into a known form."""


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True)
class NormalizedTarget:
    kind: str  # "ip" | "cidr" | "domain" | "url" | "email" | "username" | "person" | "social_handle"
    value: str  # canonical form
    raw: str  # original input

    @property
    def host(self) -> str:
        if self.kind == "url":
            parsed = urlparse(self.value)
            return parsed.hostname or ""
        return self.value


def _is_unsafe_ip(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str | None:
    """Return a human-readable reason if the network is intrinsically unsafe."""
    addr = net.network_address
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_unspecified:
        return "unspecified address (0.0.0.0/::)"
    if addr.is_reserved:
        return "reserved address"
    return None


def normalize_target(
    raw: str,
    *,
    allow_private: bool = True,
    allow_loopback: bool = False,
) -> NormalizedTarget:
    """Parse and validate *raw*.

    - ``allow_private``: when False, rejects RFC1918 / ULA ranges. Pentest
      engagements typically operate on private ranges, so the default is True.
    - ``allow_loopback``: when False (default), rejects 127.0.0.0/8 and ::1.
      The dashboard or a user-supplied ROE flag can flip this on for lab use.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidTarget("empty target")
    s = raw.strip()
    if any(c in s for c in (" ", "\t", "\n", "\r", "\x00", ";", "|", "&", "$", "`")):
        raise InvalidTarget(f"target contains forbidden characters: {raw!r}")

    # URL?
    if s.lower().startswith(("http://", "https://")):
        parsed = urlparse(s)
        if not parsed.hostname:
            raise InvalidTarget(f"URL has no host: {raw!r}")
        # Recursively validate the host portion
        host_norm = normalize_target(
            parsed.hostname,
            allow_private=allow_private,
            allow_loopback=allow_loopback,
        )
        canonical_host = host_norm.value
        netloc = canonical_host
        if parsed.port:
            netloc = f"{canonical_host}:{parsed.port}"
        canonical = f"{parsed.scheme.lower()}://{netloc}{parsed.path or ''}"
        if parsed.query:
            canonical += f"?{parsed.query}"
        return NormalizedTarget(kind="url", value=canonical, raw=raw)

    # CIDR or IP?
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise InvalidTarget(f"invalid CIDR {raw!r}: {exc}") from exc
        reason = _is_unsafe_ip(net)
        if reason and not (allow_loopback and "loopback" in reason):
            raise InvalidTarget(f"refusing CIDR {raw!r}: {reason}")
        if not allow_private and net.is_private and not net.network_address.is_loopback:
            raise InvalidTarget(f"refusing private CIDR {raw!r}")
        return NormalizedTarget(kind="cidr", value=str(net), raw=raw)

    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        ip = None
    if ip is not None:
        net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}")
        reason = _is_unsafe_ip(net)
        if reason and not (allow_loopback and "loopback" in reason):
            raise InvalidTarget(f"refusing IP {raw!r}: {reason}")
        if not allow_private and ip.is_private and not ip.is_loopback:
            raise InvalidTarget(f"refusing private IP {raw!r}")
        return NormalizedTarget(kind="ip", value=str(ip), raw=raw)

    # Domain — IDNA-encode then validate shape
    try:
        encoded = idna.encode(s, uts46=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise InvalidTarget(f"invalid domain {raw!r}: {exc}") from exc
    if not _HOSTNAME_RE.match(encoded):
        raise InvalidTarget(f"invalid hostname {raw!r}")
    # Reject IP-shaped strings that aren't valid IPs (e.g. "300.300.300.300").
    labels = encoded.split(".")
    if len(labels) == 4 and all(label.isdigit() for label in labels):
        raise InvalidTarget(f"invalid IP-shaped target {raw!r}")
    if encoded in ("localhost",) and not allow_loopback:
        raise InvalidTarget("refusing localhost target")
    return NormalizedTarget(kind="domain", value=encoded, raw=raw)


def safe_or_none(raw: str, **kw: bool) -> NormalizedTarget | None:
    try:
        return normalize_target(raw, **kw)
    except InvalidTarget:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Identity-target normalizers (Phase 8 — person-OSINT capability)
# ─────────────────────────────────────────────────────────────────────────────
# These produce ``NormalizedTarget`` values whose ``kind`` is one of
# ``email``, ``username``, ``person``, ``social_handle``. They are kept
# separate from ``normalize_target`` because the rules differ (no IDNA, no
# IP/CIDR fallback) and we want a hard boundary between infra and identity
# targets in the executor / scope validator.
# Same forbidden-character set as ``normalize_target`` — these flow into
# argv strings and we never want shell metacharacters or whitespace
# smuggled through. Kept identical so audit reasoning is consistent.
_IDENTITY_FORBIDDEN = (" ", "\t", "\n", "\r", "\x00", ";", "|", "&", "$", "`",
                       "<", ">", "*", "?", "(", ")", "[", "]", "{", "}",
                       "\\", '"', "'")
# Persons can legitimately contain spaces — they get a softer rule.
_PERSON_FORBIDDEN = ("\t", "\n", "\r", "\x00", ";", "|", "&", "$", "`",
                     "<", ">", "*", "?", "(", ")", "[", "]", "{", "}",
                     "\\", '"', "'")

_EMAIL_RE = re.compile(
    r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
# Usernames / handles: alphanumeric + underscore + dot + hyphen, 1–64 chars.
# Wide enough to cover GitHub, Twitter/X, Reddit, Telegram, etc.
_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


def normalize_email(raw: str) -> NormalizedTarget:
    if not raw or not isinstance(raw, str):
        raise InvalidTarget("empty email")
    s = raw.strip().lower()
    if any(c in s for c in _IDENTITY_FORBIDDEN):
        raise InvalidTarget(f"email contains forbidden characters: {raw!r}")
    if not _EMAIL_RE.match(s):
        raise InvalidTarget(f"invalid email shape: {raw!r}")
    return NormalizedTarget(kind="email", value=s, raw=raw)


def normalize_username(raw: str) -> NormalizedTarget:
    if not raw or not isinstance(raw, str):
        raise InvalidTarget("empty username")
    s = raw.strip().lower()
    if any(c in s for c in _IDENTITY_FORBIDDEN):
        raise InvalidTarget(f"username contains forbidden characters: {raw!r}")
    if not _USERNAME_RE.match(s):
        raise InvalidTarget(f"invalid username: {raw!r}")
    return NormalizedTarget(kind="username", value=s, raw=raw)


def normalize_social_handle(raw: str) -> NormalizedTarget:
    if not raw or not isinstance(raw, str):
        raise InvalidTarget("empty handle")
    s = raw.strip().lstrip("@").lower()
    if any(c in s for c in _IDENTITY_FORBIDDEN):
        raise InvalidTarget(f"handle contains forbidden characters: {raw!r}")
    if not _USERNAME_RE.match(s):
        raise InvalidTarget(f"invalid social handle: {raw!r}")
    return NormalizedTarget(kind="social_handle", value=s, raw=raw)


def normalize_person(raw: str) -> NormalizedTarget:
    if not raw or not isinstance(raw, str):
        raise InvalidTarget("empty person")
    s = " ".join(raw.split())
    if any(c in s for c in _PERSON_FORBIDDEN):
        raise InvalidTarget(f"person contains forbidden characters: {raw!r}")
    if len(s) < 2 or len(s) > 128:
        raise InvalidTarget(f"person name length out of range: {raw!r}")
    return NormalizedTarget(kind="person", value=s.casefold(), raw=raw)


_IDENTITY_NORMALIZERS = {
    "email": normalize_email,
    "username": normalize_username,
    "social_handle": normalize_social_handle,
    "person": normalize_person,
}


def normalize_identity(raw: str, kind: str) -> NormalizedTarget:
    """Dispatch helper. ``kind`` must be one of the four identity kinds."""
    fn = _IDENTITY_NORMALIZERS.get(kind)
    if fn is None:
        raise InvalidTarget(f"unknown identity kind: {kind!r}")
    return fn(raw)
