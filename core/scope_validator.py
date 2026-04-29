"""
core/scope_validator.py — Engagement scope enforcement.

Before any tool executes against a target, this module verifies
the target is within the authorized scope of the active engagement.
Raises ScopeViolation if not — a hard stop, not a warning.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from enum import Enum
from typing import Optional


# DNS resolution guards ---------------------------------------------------
# A misconfigured resolver (or a hostile one) can block ``getaddrinfo`` for
# minutes. The executor coroutine that calls ``assert_in_scope`` would stall
# the whole agent loop in that window. We therefore run lookups in a small
# bounded thread pool and apply a hard wall-clock timeout per call.
def _env_float(name: str, default: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "") or default)
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


_DNS_RESOLVE_TIMEOUT_S: float = _env_float("SAP_DNS_RESOLVE_TIMEOUT_S", 3.0)
_DNS_CACHE_TTL_S: float = _env_float("SAP_DNS_CACHE_TTL_S", 300.0)
_DNS_CACHE_MAX: int = _env_int("SAP_DNS_CACHE_MAX", 2048)
_DNS_POOL = ThreadPoolExecutor(
    max_workers=_env_int("SAP_DNS_POOL_WORKERS", 4),
    thread_name_prefix="sap-dns",
)


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized engagement scope."""


class IdentityKind(str, Enum):
    """Kinds of identity targets supported by the OSINT scope path."""
    EMAIL = "email"
    USERNAME = "username"
    PERSON = "person"
    SOCIAL_HANDLE = "social_handle"


class ScopeValidator:
    """
    Validates that targets (IPs, CIDRs, domains, URLs) are within
    the scope defined for an engagement.

    An empty scope means "nothing is authorized yet" — all targets
    are rejected until the engagement is properly configured.
    """

    def __init__(
        self,
        cidrs: Optional[list[str]] = None,
        domains: Optional[list[str]] = None,
        urls: Optional[list[str]] = None,
        engagement_id: str = "",
        *,
        emails: Optional[list[str]] = None,
        usernames: Optional[list[str]] = None,
        persons: Optional[list[str]] = None,
        social_handles: Optional[list[str]] = None,
    ):
        self._cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: list[str] = []
        self._urls: list[str] = []
        self._engagement_id = engagement_id
        # Maps domain → (resolved_ips, monotonic_timestamp). Bounded by
        # ``_DNS_CACHE_MAX`` with FIFO eviction; entries expire after
        # ``_DNS_CACHE_TTL_S`` seconds.
        self._domain_ip_cache: dict[str, tuple[set[str], float]] = {}

        for cidr in (cidrs or []):
            try:
                self._cidrs.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

        for domain in (domains or []):
            self._domains.append(domain.lower().strip())

        for url in (urls or []):
            self._urls.append(url.lower().strip())

        # Identity scope (Phase 8 — person-OSINT). Stored already normalized
        # by the Pydantic model; we still defensively re-normalize here in
        # case a caller constructs the validator directly with raw strings.
        self._emails: set[str] = {s.strip().lower() for s in (emails or []) if s and s.strip()}
        self._usernames: set[str] = {s.strip().lower() for s in (usernames or []) if s and s.strip()}
        self._social_handles: set[str] = {
            s.strip().lstrip("@").lower()
            for s in (social_handles or []) if s and s.strip().lstrip("@")
        }
        self._persons: set[str] = {
            " ".join(s.split()).casefold()
            for s in (persons or []) if s and s.strip()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assert_in_scope(self, target: str, engagement_id: str = "") -> None:
        """
        Raises ScopeViolation if *target* is not authorized.
        *target* can be an IP, CIDR, hostname/domain, or URL.

        Every target is first run through ``core.target_validator.normalize_target``
        which rejects malformed inputs, shell-meta characters, loopback /
        link-local / multicast and IDN-spoofed hosts. Engagement scope is
        then evaluated against the canonical (IDNA-encoded, lowercased,
        collapsed) form.
        """
        # Defensive normalization first — this rejects shell-injection,
        # localhost bypass attempts, IDN homoglyphs, etc., regardless of
        # whether the engagement scope happens to allow them.
        from core.target_validator import InvalidTarget, normalize_target

        try:
            normalized = normalize_target(target, allow_loopback=False)
        except InvalidTarget as exc:
            raise ScopeViolation(
                f"Target {target!r} rejected by validator: {exc}"
            ) from exc
        target = normalized.value

        if not self._cidrs and not self._domains and not self._urls:
            raise ScopeViolation(
                "No infrastructure scope defined for this engagement. "
                "Configure scope_cidrs, scope_domains, or scope_urls first. "
                "If this target is a person/email/username/handle, use the "
                "identity scope instead (scope_emails, scope_usernames, "
                "scope_persons, scope_social_handles) and invoke the OSINT "
                "MCP variant of the tool — infrastructure scope does not "
                "apply to PII targets."
            )

        if self._is_ip_or_cidr(target):
            if self._ip_in_scope(target):
                return
            # If CIDRs are empty but domains are authorized, allow direct-IP
            # targets that match DNS A/AAAA records of authorized domains.
            if self._is_ip_only(target) and self._ip_matches_authorized_domain(target):
                return
        elif target.startswith("http://") or target.startswith("https://"):
            if self._url_in_scope(target):
                return
        else:
            if self._domain_in_scope(target):
                return
            # also try interpreting as IP (no CIDR notation)
            if self._is_ip_only(target) and self._ip_in_scope(target):
                return

        raise ScopeViolation(
            f"Target '{target}' is OUTSIDE the authorized scope "
            f"for engagement '{self._engagement_id or engagement_id}'. "
            f"Authorized CIDRs: {[str(n) for n in self._cidrs]}, "
            f"domains: {self._domains}. "
            f"Obtain written authorization before testing this target."
        )

    def is_in_scope(self, target: str) -> bool:
        """Returns True if target is in scope, False otherwise (no exception)."""
        try:
            self.assert_in_scope(target)
            return True
        except ScopeViolation:
            return False

    # ------------------------------------------------------------------
    # Identity scope (Phase 8 — person-OSINT)
    # ------------------------------------------------------------------

    def assert_identity_in_scope(
        self,
        value: str,
        kind: IdentityKind | str,
        engagement_id: str = "",
    ) -> None:
        """Raise ``ScopeViolation`` if *value* is not in the identity scope.

        Hard-match semantics: the value must appear (after normalization)
        in the engagement's corresponding identity list. There is no DNS
        fallback, no "endswith" pattern — identity is opt-in per target.
        """
        from core.target_validator import InvalidTarget, normalize_identity

        kind_str = kind.value if isinstance(kind, IdentityKind) else str(kind)
        try:
            norm = normalize_identity(value, kind_str)
        except InvalidTarget as exc:
            raise ScopeViolation(
                f"Identity target {value!r} ({kind_str}) rejected: {exc}"
            ) from exc

        bucket = {
            "email": self._emails,
            "username": self._usernames,
            "social_handle": self._social_handles,
            "person": self._persons,
        }[kind_str]

        # Cross-bucket fallback: usernames and social handles share the same
        # syntactic shape and most OSINT tools (sherlock, maigret, …) treat
        # them as interchangeable. If the primary bucket does not contain the
        # value, look it up in the sibling bucket before refusing.
        sibling: set[str] = set()
        sibling_kind: str | None = None
        if kind_str == "username":
            sibling, sibling_kind = self._social_handles, "social_handle"
        elif kind_str == "social_handle":
            sibling, sibling_kind = self._usernames, "username"

        if not bucket and not sibling:
            raise ScopeViolation(
                f"No {kind_str} scope defined for engagement "
                f"'{self._engagement_id or engagement_id}'. Add the value to "
                f"scope_{kind_str}s before running OSINT tools against it."
            )
        if norm.value not in bucket and norm.value not in sibling:
            extra = (
                f", {sibling_kind}s: {sorted(sibling)}" if sibling_kind else ""
            )
            raise ScopeViolation(
                f"Identity target {norm.value!r} ({kind_str}) is OUTSIDE the "
                f"authorized OSINT scope for engagement "
                f"'{self._engagement_id or engagement_id}'. "
                f"Authorized {kind_str}s: {sorted(bucket)}{extra}."
            )

    def is_identity_in_scope(self, value: str, kind: IdentityKind | str) -> bool:
        try:
            self.assert_identity_in_scope(value, kind)
            return True
        except ScopeViolation:
            return False

    @property
    def has_identity_scope(self) -> bool:
        """True if any identity bucket is non-empty."""
        return bool(self._emails or self._usernames or self._persons or self._social_handles)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ip_or_cidr(target: str) -> bool:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_ip_only(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def _ip_in_scope(self, target: str) -> bool:
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for authorized in self._cidrs:
            # target IP/CIDR must be a subnet of (or equal to) authorized
            if net.subnet_of(authorized) or net == authorized:  # type: ignore[arg-type]
                return True
        return False

    def _domain_in_scope(self, target: str) -> bool:
        target = target.lower().strip()
        for authorized in self._domains:
            if target == authorized or target.endswith("." + authorized):
                return True
        return False

    def _url_in_scope(self, target: str) -> bool:
        # Extract hostname from URL
        match = re.match(r"https?://([^/:?#]+)", target.lower())
        if not match:
            return False
        host = match.group(1)
        # Check as domain first
        if self._domain_in_scope(host):
            return True
        # Check as IP
        if self._is_ip_only(host) and self._ip_in_scope(host):
            return True
        # Check full URL prefix match
        for authorized_url in self._urls:
            if target.startswith(authorized_url):
                return True
        return False

    def _ip_matches_authorized_domain(self, ip_target: str) -> bool:
        """Return True if *ip_target* is one of the authorized domains' A/AAAA."""
        try:
            ip_norm = str(ipaddress.ip_address(ip_target))
        except ValueError:
            return False

        for domain in self._domains:
            resolved = self._resolve_domain_ips(domain)
            if ip_norm in resolved:
                return True
        return False

    def _resolve_domain_ips(self, domain: str) -> set[str]:
        """Resolve domain to normalized IP strings (A/AAAA), with bounded TTL cache.

        ``getaddrinfo`` is run in a worker thread with a hard wall-clock cap
        (``_DNS_RESOLVE_TIMEOUT_S``) so a slow / unreachable resolver cannot
        block the caller indefinitely. Results are cached for
        ``_DNS_CACHE_TTL_S`` seconds to amortize lookups across calls; the
        cache itself is bounded at ``_DNS_CACHE_MAX`` entries (FIFO eviction)
        to prevent unbounded growth in long-lived processes.
        """
        import time as _time

        now = _time.monotonic()
        cached = self._domain_ip_cache.get(domain)
        if cached is not None:
            ips, ts = cached
            if now - ts < _DNS_CACHE_TTL_S:
                return ips

        ips: set[str] = set()

        def _lookup() -> set[str]:
            out: set[str] = set()
            try:
                infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                return out
            for info in infos:
                sockaddr = info[4]
                if not sockaddr:
                    continue
                host = sockaddr[0]
                try:
                    out.add(str(ipaddress.ip_address(host)))
                except ValueError:
                    continue
            return out

        try:
            fut = _DNS_POOL.submit(_lookup)
            ips = fut.result(timeout=_DNS_RESOLVE_TIMEOUT_S)
        except FuturesTimeoutError:
            # Best-effort cancel; the worker thread keeps running on the
            # blocking syscall until the resolver itself unblocks. We simply
            # treat the lookup as a miss and cache an empty set briefly so
            # repeated calls within TTL do not pile up worker threads.
            ips = set()
        except Exception:
            ips = set()

        # Bounded FIFO cache.
        if len(self._domain_ip_cache) >= _DNS_CACHE_MAX:
            try:
                oldest_key = next(iter(self._domain_ip_cache))
                self._domain_ip_cache.pop(oldest_key, None)
            except StopIteration:
                pass
        self._domain_ip_cache[domain] = (ips, now)
        return ips
