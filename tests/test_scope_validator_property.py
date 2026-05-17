"""Property-based tests for the scope chokepoint (`core/scope_validator.py`).

The scope validator is one of the four immutable security chokepoints. Any
bypass here grants out-of-scope tool execution. These tests pound the
public surface with thousands of random inputs to catch the unsafe
generalisations that ad-hoc unit tests miss:

* "any CIDR outside scope is rejected" (no wildcard / family confusion)
* "identity match is hard-match, case-insensitive, no wildcard" (no
  endswith / contains bypass)
* "empty scope rejects every infra target" (no fail-open)
* "empty identity scope rejects every PII target"
* "the cross-bucket username ↔ social_handle fallback never widens scope
  beyond the two buckets"

Hypothesis is configured to run a generous number of cases per test so a
single missing branch surfaces during CI rather than during an
engagement.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from core.scope_validator import ScopeValidator, ScopeViolation

# A budget that catches realistic bypasses without slowing CI; the property
# tests are read-only and complete in well under a second each.
SAMPLES = 500


# ── Strategies ────────────────────────────────────────────────────────────

def _ipv4_in_cidr(cidr: str) -> st.SearchStrategy[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return st.integers(
        min_value=int(net.network_address),
        max_value=int(net.broadcast_address),
    ).map(lambda i: str(ipaddress.IPv4Address(i)))


def _ipv4_outside_cidrs(cidrs: list[str]) -> st.SearchStrategy[str]:
    nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]

    def _outside(addr: str) -> bool:
        ip = ipaddress.IPv4Address(addr)
        return not any(ip in n for n in nets)

    return (
        st.integers(min_value=1, max_value=(2**32) - 2)
        .map(lambda i: str(ipaddress.IPv4Address(i)))
        .filter(_outside)
    )


# Public unicast space, excluding obvious bogons + loopback + RFC1918 +
# multicast that ``normalize_target`` rejects upfront.
_PUBLIC_RANGES = [
    ipaddress.ip_network("8.0.0.0/8"),
    ipaddress.ip_network("13.0.0.0/8"),
    ipaddress.ip_network("23.0.0.0/8"),
]


def _public_ipv4() -> st.SearchStrategy[str]:
    return st.sampled_from(_PUBLIC_RANGES).flatmap(
        lambda net: st.integers(
            min_value=int(net.network_address) + 1,
            max_value=int(net.broadcast_address) - 1,
        ).map(lambda i: str(ipaddress.IPv4Address(i)))
    )


# Labels that survive ``normalize_target`` (lowercase ASCII, hyphen-safe).
_DOMAIN_LABEL = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789",
    min_size=1,
    max_size=20,
)


def _domain() -> st.SearchStrategy[str]:
    return st.lists(_DOMAIN_LABEL, min_size=2, max_size=4).map(".".join)


_USERNAME = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=1,
    max_size=20,
)


def _email() -> st.SearchStrategy[str]:
    return st.tuples(_USERNAME, _domain()).map(lambda t: f"{t[0]}@{t[1]}")


# ── Infrastructure scope properties ──────────────────────────────────────


@given(target=st.text(min_size=1, max_size=30))
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_empty_scope_rejects_every_target(target):
    """A validator with no infra scope must reject every target — fail closed."""
    sv = ScopeValidator()
    with pytest.raises(ScopeViolation):
        sv.assert_in_scope(target)


@given(addr=_ipv4_in_cidr("203.0.113.0/24"))
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_any_ip_inside_declared_cidr_is_accepted(addr):
    sv = ScopeValidator(cidrs=["203.0.113.0/24"])
    sv.assert_in_scope(addr)  # must not raise


@given(addr=_ipv4_outside_cidrs(["203.0.113.0/24"]))
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_no_ip_outside_declared_cidrs_passes(addr):
    """No IPv4 outside the declared CIDRs may pass scope.

    The validator also normalizes (rejects loopback / link-local /
    multicast / RFC1918) before scope evaluation. Both rejection paths
    are acceptable for this property — the chokepoint is "not accepted".
    """
    sv = ScopeValidator(cidrs=["203.0.113.0/24"])
    with pytest.raises(ScopeViolation):
        sv.assert_in_scope(addr)


@given(label=_DOMAIN_LABEL)
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_domain_suffix_match_does_not_admit_arbitrary_subdomains(label):
    """Suffix matching must not turn into "contains" matching.

    Authorising ``example.com`` allows ``foo.example.com`` but NOT a
    domain that merely *contains* the string ``example.com`` (e.g.
    ``evilexample.com.attacker.io``).
    """
    sv = ScopeValidator(domains=["example.com"])
    intruder = f"{label}example.com"  # "fooexample.com" — different domain
    if intruder == "example.com":
        return  # degenerate label, skip
    with pytest.raises(ScopeViolation):
        sv.assert_in_scope(intruder)


# ── Identity scope properties ────────────────────────────────────────────


@given(value=st.text(min_size=1, max_size=30))
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_empty_identity_scope_rejects_every_email(value):
    sv = ScopeValidator()
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope(value, "email")


@given(email=_email())
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_email_in_scope_is_accepted_case_insensitively(email):
    sv = ScopeValidator(emails=[email.upper()])
    # Identity normalisation must make matching case-insensitive.
    sv.assert_identity_in_scope(email, "email")
    sv.assert_identity_in_scope(email.upper(), "email")
    sv.assert_identity_in_scope(email.lower(), "email")


@given(email=_email(), other=_email())
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_email_not_in_scope_is_always_rejected(email, other):
    if email.lower() == other.lower():
        return
    sv = ScopeValidator(emails=[email])
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope(other, "email")


@given(authorised=_email(), prefix=_USERNAME)
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_identity_email_match_is_hard_match_no_wildcard(authorised, prefix):
    """Authorising ``alice@example.com`` MUST NOT allow ``bob@example.com``
    or ``prefix+alice@example.com``."""
    sv = ScopeValidator(emails=[authorised])
    local, _, domain = authorised.partition("@")
    cousin = f"{prefix}{local}@{domain}"
    if cousin.lower() == authorised.lower():
        return
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope(cousin, "email")


@given(handle=_USERNAME, other=_USERNAME)
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_username_social_cross_bucket_fallback_is_symmetric(handle, other):
    """A value authorised as ``username`` is accepted as ``social_handle``
    (and vice-versa) but never any other value sneaks in via that path."""
    if handle.lower() == other.lower():
        return
    sv = ScopeValidator(usernames=[handle])
    # Same value via the sibling bucket → allowed.
    sv.assert_identity_in_scope(handle, "social_handle")
    # Different value via either bucket → rejected.
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope(other, "username")
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope(other, "social_handle")


@given(name_a=_USERNAME, name_b=_USERNAME)
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_person_match_is_normalised_whitespace_insensitive(name_a, name_b):
    """Persons are matched casefolded with collapsed internal whitespace.

    ``"  Alice   Liddell  "`` and ``"alice liddell"`` are the same person;
    any other casefold/whitespace string is not.
    """
    full = f"{name_a} {name_b}"
    sv = ScopeValidator(persons=[full.upper()])
    # Spacing collapse + casefolding both supported.
    sv.assert_identity_in_scope(f"  {name_a}    {name_b}  ", "person")
    sv.assert_identity_in_scope(full.lower(), "person")
    # Completely unrelated string → reject.
    intruder = f"{name_a}xxx {name_b}yyy"
    if intruder.casefold() != full.casefold():
        with pytest.raises(ScopeViolation):
            sv.assert_identity_in_scope(intruder, "person")


# ── Fail-closed guarantee on misuse ──────────────────────────────────────


@given(addr=_public_ipv4())
@settings(max_examples=SAMPLES, suppress_health_check=[HealthCheck.too_slow])
def test_is_in_scope_never_raises_on_unauthorised_input(addr):
    """``is_in_scope`` is the boolean variant: it must NEVER propagate."""
    sv = ScopeValidator(cidrs=["203.0.113.0/24"])
    result = sv.is_in_scope(addr)
    assert result is False  # everything is outside the authorised /24
