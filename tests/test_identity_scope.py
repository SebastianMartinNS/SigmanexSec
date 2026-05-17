"""
tests/test_identity_scope.py — Phase 8 (person-OSINT) foundation tests.

Covers:
  - identity normalizers (email/username/handle/person)
  - ScopeValidator.assert_identity_in_scope hard-match semantics
  - ToolExecutor.run() mutual exclusion of target / identity_target
  - Engagement legacy DB rows load with default-empty identity scope
  - Pydantic EngagementCreate validators normalize identity inputs
"""
from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from core.executor import SecurityError, ToolExecutor
from core.models import Engagement, EngagementCreate
from core.scope_validator import IdentityKind, ScopeValidator, ScopeViolation
from core.session_store import SessionStore
from core.target_validator import (
    InvalidTarget,
    normalize_email,
    normalize_identity,
    normalize_person,
    normalize_social_handle,
    normalize_username,
)

# ── Normalizers ─────────────────────────────────────────────────────────────

def test_normalize_email_ok():
    n = normalize_email("  Foo.Bar@Example.COM ")
    assert n.kind == "email"
    assert n.value == "foo.bar@example.com"


@pytest.mark.parametrize("bad", ["", "no-at", "a@b", "a b@c.d", "a@c.d;ls", "a@@c.d"])
def test_normalize_email_rejects(bad):
    with pytest.raises(InvalidTarget):
        normalize_email(bad)


def test_normalize_username_and_handle():
    assert normalize_username("OctoCat").value == "octocat"
    assert normalize_social_handle("@OctoCat").value == "octocat"
    with pytest.raises(InvalidTarget):
        normalize_username("with space")
    with pytest.raises(InvalidTarget):
        normalize_social_handle("hi;rm")


def test_normalize_person_collapses_whitespace():
    n = normalize_person("  Alice    Smith ")
    assert n.kind == "person"
    assert n.value == "alice smith"
    with pytest.raises(InvalidTarget):
        normalize_person("a")  # too short


def test_normalize_identity_dispatch_unknown():
    with pytest.raises(InvalidTarget):
        normalize_identity("x", "phone")


# ── ScopeValidator hard-match ──────────────────────────────────────────────

def test_scope_identity_hard_match_email():
    sv = ScopeValidator(emails=["alice@example.com"])
    sv.assert_identity_in_scope("Alice@Example.COM", IdentityKind.EMAIL)
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope("bob@example.com", IdentityKind.EMAIL)


def test_scope_identity_handle_strips_at():
    sv = ScopeValidator(social_handles=["octocat"])
    sv.assert_identity_in_scope("@OctoCat", IdentityKind.SOCIAL_HANDLE)


def test_scope_identity_empty_bucket_raises():
    sv = ScopeValidator()  # nothing set
    with pytest.raises(ScopeViolation):
        sv.assert_identity_in_scope("alice@example.com", IdentityKind.EMAIL)


def test_scope_identity_string_kind_accepted():
    sv = ScopeValidator(usernames=["octocat"])
    sv.assert_identity_in_scope("octocat", "username")  # string instead of enum


def test_has_identity_scope_property():
    assert ScopeValidator(emails=["a@b.com"]).has_identity_scope is True
    assert ScopeValidator(cidrs=["10.0.0.0/24"]).has_identity_scope is False


def test_assert_in_scope_does_not_consult_identity():
    """Infra path must NOT see identity buckets — keeps the two paths
    cleanly separated for audit."""
    sv = ScopeValidator(emails=["alice@example.com"])
    with pytest.raises(ScopeViolation):
        sv.assert_in_scope("alice@example.com")


# ── Executor mutual exclusion ──────────────────────────────────────────────

def test_executor_target_and_identity_mutex(monkeypatch):
    exe = ToolExecutor()
    exe._scope = ScopeValidator(emails=["a@b.com"])
    # Bypass the allowlist check so we exercise the mutex specifically.
    monkeypatch.setattr(ToolExecutor, "_check_tool", staticmethod(lambda t: None))

    async def _go():
        with pytest.raises(SecurityError, match="mutually exclusive"):
            await exe.run(
                "echo", ["x"],
                target="example.com",
                identity_target=("a@b.com", "email"),
            )

    asyncio.run(_go())


def test_executor_identity_scope_violation_propagates(monkeypatch):
    exe = ToolExecutor()
    exe._scope = ScopeValidator(emails=["alice@example.com"])
    monkeypatch.setattr(ToolExecutor, "_check_tool", staticmethod(lambda t: None))

    async def _go():
        with pytest.raises(ScopeViolation):
            await exe.run(
                "echo", ["x"],
                identity_target=("bob@example.com", "email"),
            )

    asyncio.run(_go())


# ── Pydantic EngagementCreate validators ────────────────────────────────────

def test_engagement_create_normalizes_identity():
    ec = EngagementCreate(
        name="t", client="c",
        scope_emails=["  Alice@Example.COM "],
        scope_usernames=["OctoCat"],
        scope_social_handles=["@OctoCat"],
        scope_persons=["  Alice   Smith "],
        osint_authorization_ref="ROE-2026-001",
    )
    assert ec.scope_emails == ["alice@example.com"]
    assert ec.scope_usernames == ["octocat"]
    assert ec.scope_social_handles == ["octocat"]
    assert ec.scope_persons == ["alice smith"]


def test_engagement_create_rejects_bad_email():
    with pytest.raises(ValidationError):
        EngagementCreate(name="t", client="c", scope_emails=["not-an-email"])


# ── DB backward-compat: legacy row load ─────────────────────────────────────

def test_session_store_loads_legacy_engagement(tmp_paths):
    """An engagement row written without the identity columns must still
    load — the migration adds the columns and ``_row_to_engagement``
    defaults missing values to []/'' via the _opt helper."""
    db_path = tmp_paths["sessions"] / "legacy.db"
    # Create legacy schema (no identity cols) and insert one row.
    import sqlite3
    con = sqlite3.connect(db_path)
    con.executescript("""
    CREATE TABLE engagements (
        id TEXT PRIMARY KEY, name TEXT, client TEXT,
        scope_cidrs TEXT, scope_domains TEXT, scope_urls TEXT,
        roe TEXT, tester TEXT, auth_ref TEXT,
        status TEXT, phase TEXT, created_at TEXT, updated_at TEXT
    );
    """)
    con.execute(
        "INSERT INTO engagements VALUES "
        "('eng1','t','c','[]','[]','[]','','','','active','scoping',"
        "'2026-04-27T10:00:00','2026-04-27T10:00:00')"
    )
    con.commit()
    con.close()

    store = SessionStore(str(db_path))

    async def _go():
        await store.init()  # runs the identity migration
        eng = await store.get_engagement("eng1")
        assert eng is not None
        assert eng.scope_emails == []
        assert eng.scope_usernames == []
        assert eng.scope_persons == []
        assert eng.scope_social_handles == []
        assert eng.osint_authorization_ref == ""

    asyncio.run(_go())


def test_session_store_roundtrip_with_identity(tmp_paths):
    db_path = tmp_paths["sessions"] / "rt.db"
    store = SessionStore(str(db_path))

    async def _go():
        await store.init()
        eng = Engagement(
            name="t", client="c",
            scope_emails=["alice@example.com"],
            scope_usernames=["octocat"],
            osint_authorization_ref="ROE-001",
        )
        await store.create_engagement(eng)
        loaded = await store.get_engagement(eng.id)
        assert loaded is not None
        assert loaded.scope_emails == ["alice@example.com"]
        assert loaded.scope_usernames == ["octocat"]
        assert loaded.osint_authorization_ref == "ROE-001"

    asyncio.run(_go())
