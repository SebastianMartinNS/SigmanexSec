from __future__ import annotations

import socket

import pytest

from core.scope_validator import ScopeValidator, ScopeViolation


def _v():
    return ScopeValidator(
        cidrs=["10.0.0.0/24"],
        domains=["example.com"],
        engagement_id="eng-1",
    )


def test_in_scope_ip_passes():
    _v().assert_in_scope("10.0.0.5")


def test_out_of_scope_ip_rejected():
    with pytest.raises(ScopeViolation):
        _v().assert_in_scope("8.8.8.8")


def test_loopback_rejected_even_when_scope_silent():
    sv = ScopeValidator(cidrs=["127.0.0.0/8"], engagement_id="eng-2")
    with pytest.raises(ScopeViolation, match="rejected by validator"):
        sv.assert_in_scope("127.0.0.1")


def test_shell_injection_rejected():
    with pytest.raises(ScopeViolation, match="rejected by validator"):
        _v().assert_in_scope("10.0.0.5; rm -rf /")


def test_idn_normalized_then_scoped():
    sv = ScopeValidator(domains=["xn--bcher-kva.example"], engagement_id="eng-3")
    sv.assert_in_scope("bücher.example")


def test_ip_allowed_when_resolved_from_authorized_domain(monkeypatch: pytest.MonkeyPatch):
    sv = ScopeValidator(domains=["sigmanex.net"], engagement_id="eng-4")

    def _fake_getaddrinfo(host, *_args, **_kwargs):
        assert host == "sigmanex.net"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("80.211.136.13", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    sv.assert_in_scope("80.211.136.13")


def test_ip_rejected_when_not_resolved_from_authorized_domain(monkeypatch: pytest.MonkeyPatch):
    sv = ScopeValidator(domains=["sigmanex.net"], engagement_id="eng-5")

    def _fake_getaddrinfo(host, *_args, **_kwargs):
        assert host == "sigmanex.net"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("80.211.136.13", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    with pytest.raises(ScopeViolation):
        sv.assert_in_scope("8.8.8.8")
