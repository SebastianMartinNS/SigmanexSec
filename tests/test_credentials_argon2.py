"""Tests for core/credentials.py (Argon2id wrapper) and the dashboard
RBAC layer (sap_dashboard.backend.rbac) that consumes it."""

from __future__ import annotations

import json

import pytest

from core import credentials

# ── Core credentials API ─────────────────────────────────────────────────


def test_hash_password_produces_argon2id_encoded_value():
    h = credentials.hash_password("hunter2-correct-horse")
    assert h.startswith("$argon2id$")
    # OWASP-baseline params we declared in core.credentials.
    assert "m=65536" in h
    assert "t=3" in h
    assert "p=4" in h


def test_hash_password_refuses_empty():
    with pytest.raises(ValueError):
        credentials.hash_password("")


def test_verify_password_roundtrip():
    h = credentials.hash_password("hunter2-correct-horse")
    assert credentials.verify_password("hunter2-correct-horse", h) is True
    assert credentials.verify_password("WRONG", h) is False


def test_verify_password_rejects_plaintext_as_stored():
    """The verify path MUST refuse to compare against a plaintext "hash".
    Otherwise a misconfigured directory could silently authenticate."""
    assert credentials.verify_password("hunter2", "hunter2") is False
    assert credentials.verify_password("hunter2", "$bcrypt$something") is False


def test_verify_password_rejects_empty_inputs():
    h = credentials.hash_password("hunter2-correct-horse")
    assert credentials.verify_password("", h) is False
    assert credentials.verify_password("hunter2-correct-horse", "") is False
    assert credentials.verify_password("hunter2-correct-horse", None) is False


def test_needs_rehash_false_for_freshly_hashed():
    h = credentials.hash_password("hunter2-correct-horse")
    assert credentials.needs_rehash(h) is False


def test_needs_rehash_true_for_non_argon2id():
    assert credentials.needs_rehash("plaintext") is True
    assert credentials.needs_rehash("$bcrypt$something") is True


def test_looks_like_argon2id_shape_check():
    assert credentials.looks_like_argon2id("$argon2id$v=19$m=65536,t=3,p=4$...$...")
    assert credentials.looks_like_argon2id("$argon2i$...")
    assert credentials.looks_like_argon2id("$argon2d$...")
    assert not credentials.looks_like_argon2id("plaintext")
    assert not credentials.looks_like_argon2id("$bcrypt$...")
    assert not credentials.looks_like_argon2id("")
    assert not credentials.looks_like_argon2id(None)


def test_generate_random_password_minimum_length():
    p = credentials.generate_random_password()
    assert isinstance(p, str)
    assert len(p) >= 24
    with pytest.raises(ValueError):
        credentials.generate_random_password(length=8)


# ── RBAC integration ─────────────────────────────────────────────────────


@pytest.fixture
def _reset_rbac_env(monkeypatch):
    """Strip every dashboard-auth env var so each test starts clean."""
    for var in (
        "SAP_DASHBOARD_USER", "SAP_DASHBOARD_PASS",
        "SAP_DASHBOARD_USERS",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def test_rbac_verify_with_argon2id_pass_hash(_reset_rbac_env, monkeypatch):
    """A directory entry with `pass_hash` (Argon2id) verifies correctly."""
    alice_pass = "rTfYf-aliCe-1234567890"
    directory = {
        "alice": {
            "pass_hash": credentials.hash_password(alice_pass),
            "role": "operator",
        },
    }
    monkeypatch.setenv("SAP_DASHBOARD_USERS", json.dumps(directory))

    from sap_dashboard.backend import rbac
    assert rbac.verify_user_password("alice", alice_pass) == "operator"
    assert rbac.verify_user_password("alice", "wrong") is None
    assert rbac.verify_user_password("unknown", alice_pass) is None


def test_rbac_verify_with_legacy_plaintext_still_works(
    _reset_rbac_env, monkeypatch
):
    """The legacy `pass` plaintext format must still authenticate during
    the v2.3 grace period — and emit the deprecation audit event."""
    directory = {
        "bob": {"pass": "bobs-plaintext-only-pwd!!", "role": "viewer"},
    }
    monkeypatch.setenv("SAP_DASHBOARD_USERS", json.dumps(directory))

    from sap_dashboard.backend import rbac
    assert rbac.verify_user_password("bob", "bobs-plaintext-only-pwd!!") == "viewer"
    assert rbac.verify_user_password("bob", "wrong") is None


def test_rbac_pass_hash_takes_precedence_over_pass(_reset_rbac_env, monkeypatch):
    """If both fields are present, pass_hash wins and the plaintext is
    discarded (so a forgotten plaintext cannot create a back-door)."""
    real_pass = "hashed-pwd-2026-correct"
    directory = {
        "carol": {
            "pass_hash": credentials.hash_password(real_pass),
            "pass": "bogus-leftover-plaintext",
            "role": "admin",
        },
    }
    monkeypatch.setenv("SAP_DASHBOARD_USERS", json.dumps(directory))

    from sap_dashboard.backend import rbac
    assert rbac.verify_user_password("carol", real_pass) == "admin"
    assert rbac.verify_user_password("carol", "bogus-leftover-plaintext") is None


def test_rbac_rejects_non_argon2id_pass_hash_value(_reset_rbac_env, monkeypatch):
    """A directory entry that DECLARES `pass_hash` but ships a non-Argon2id
    value must be rejected at directory-load time so callers cannot guess."""
    directory = {
        "dave": {"pass_hash": "$bcrypt$bogus", "role": "viewer"},
    }
    monkeypatch.setenv("SAP_DASHBOARD_USERS", json.dumps(directory))

    from sap_dashboard.backend import rbac
    # Entry dropped → user is unknown.
    assert rbac.verify_user_password("dave", "anything") is None
    assert rbac.lookup_role("dave") is None


def test_legacy_bootstrap_user_grafted_as_admin_with_hash(
    _reset_rbac_env, monkeypatch
):
    """SAP_DASHBOARD_USER + SAP_DASHBOARD_PASS as an Argon2id hash gives the
    admin role and verifies via the hash path."""
    pwd = "bootstrap-correct-horse-staple"
    monkeypatch.setenv("SAP_DASHBOARD_USER", "boot")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", credentials.hash_password(pwd))

    from sap_dashboard.backend import rbac
    assert rbac.verify_user_password("boot", pwd) == "admin"
    assert rbac.lookup_role("boot") == "admin"


def test_legacy_bootstrap_user_grafted_as_admin_with_plaintext(
    _reset_rbac_env, monkeypatch
):
    """Same bootstrap path with plaintext PASS still authenticates (legacy
    fallback) and reports admin role."""
    monkeypatch.setenv("SAP_DASHBOARD_USER", "boot")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "bootstrap-plaintext-1234")

    from sap_dashboard.backend import rbac
    assert rbac.verify_user_password("boot", "bootstrap-plaintext-1234") == "admin"
    assert rbac.lookup_role("boot") == "admin"
