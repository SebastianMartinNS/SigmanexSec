"""Integration tests for mcp_servers/osint_server.py.

Strategy
--------
We don't run the real binaries here — instead we monkeypatch
``ToolExecutor.run`` to return a canned ``ExecutionResult`` so we can
exercise:
  1. authorization gate (``osint_authorization_ref`` required),
  2. scope gate (target must be in the matching identity bucket),
  3. parser correctness (sherlock/holehe/maigret/h8mail),
  4. response shape (``tool``, ``target``, ``target_kind``, ``accounts``).

We also assert the parsers in isolation (no executor needed) for speed.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from core.models import Engagement, EngagementCreate
from core.session_store import SessionStore


# ── Parser unit tests ────────────────────────────────────────────────────────

def test_parse_sherlock():
    from mcp_servers.osint_server import _parse_sherlock
    out = (
        "[*] Checking username octocat on:\n"
        "[+] GitHub: https://github.com/octocat\n"
        "[+] Twitter: https://twitter.com/octocat\n"
        "[-] Not Found: https://example.com/octocat\n"
    )
    accounts = _parse_sherlock(out)
    assert {a["platform"] for a in accounts} == {"GitHub", "Twitter"}
    assert all(a["url"].startswith("https://") for a in accounts)
    assert all(a["confidence"] == "high" for a in accounts)


def test_parse_holehe():
    from mcp_servers.osint_server import _parse_holehe
    out = "[+] github.com\n[+] twitter.com\n[-] facebook.com\n"
    accounts = _parse_holehe(out)
    assert {a["platform"] for a in accounts} == {"github.com", "twitter.com"}


def test_parse_maigret():
    from mcp_servers.osint_server import _parse_maigret
    out = "[+] GitHub: https://github.com/octocat\n[+] HackerNews: https://news.ycombinator.com/user?id=octocat\n"
    accounts = _parse_maigret(out)
    assert len(accounts) == 2
    assert accounts[0]["confidence"] == "medium"


def test_parse_h8mail():
    from mcp_servers.osint_server import _parse_h8mail
    out = "[+] target: alice@example.com\n[+] LinkedIn breach (2012)\n[+] Dropbox leak (2016)\n[-] no breach\n"
    parsed = _parse_h8mail(out)
    assert len(parsed["breaches"]) == 2
    assert "LinkedIn" in parsed["breaches"][0]


def test_parse_json_safe_full():
    from mcp_servers.osint_server import _parse_json_safe
    assert _parse_json_safe('{"a": 1}') == {"a": 1}
    assert _parse_json_safe('[1, 2, 3]') == [1, 2, 3]
    assert _parse_json_safe('garbage\n{"k":"v"}') == {"k": "v"}
    assert _parse_json_safe('') is None
    assert _parse_json_safe('not json') is None


# ── Tool integration tests with stubbed executor ────────────────────────────


@pytest.fixture
def osint_eng(tmp_paths) -> Engagement:
    """Create an engagement with identity scope + osint auth."""
    create = EngagementCreate(
        name="OSINT QA",
        client="self",
        tester="qa",
        authorization_ref="ROE-INFRA-1",
        osint_authorization_ref="ROE-OSINT-1",
        scope_emails=["alice@example.com"],
        scope_usernames=["octocat", "alice"],
        scope_persons=["alice doe"],
        scope_social_handles=["alice"],
        scope_domains=["example.com"],
    )
    eng = Engagement(**create.model_dump())

    async def _setup():
        from mcp_servers import osint_server as _osint
        await _osint.store.init()
        await _osint.store.create_engagement(eng)

    asyncio.run(_setup())
    return eng


def _patch_exe_run(monkeypatch, stdout: str, returncode: int = 0):
    """Replace ToolExecutor.run with an awaitable returning canned output.

    The fake honors the scope/identity gate by replicating the check that
    the real ``ToolExecutor.run`` performs — otherwise out-of-scope tests
    would silently succeed. We also bypass the binary allowlist.
    """
    from mcp_servers import osint_server as srv
    from core.scope_validator import ScopeViolation

    async def fake_run(self, *args, **kwargs):
        identity = kwargs.get("identity_target")
        if identity is not None and self._scope is not None:
            value, kind = identity
            self._scope.assert_identity_in_scope(value, kind, kwargs.get("engagement_id", ""))
        target = kwargs.get("target")
        if target is not None and self._scope is not None:
            self._scope.assert_in_scope(target, kwargs.get("engagement_id", ""))
        return SimpleNamespace(
            command="fake-tool fake-arg",
            returncode=returncode,
            duration_seconds=0.1,
            stdout=stdout,
            stderr="",
            call_id="qa-call-id",
            truncated=False,
        )

    monkeypatch.setattr(srv._exe.__class__, "run", fake_run)


def test_sherlock_run_happy_path(osint_eng, monkeypatch):
    from mcp_servers.osint_server import sherlock_run

    _patch_exe_run(
        monkeypatch,
        "[+] GitHub: https://github.com/octocat\n[+] Twitter: https://twitter.com/octocat\n",
    )
    res = asyncio.run(sherlock_run(
        engagement_id=osint_eng.id, username="octocat",
    ))
    assert "error" not in res, res
    assert res["tool"] == "sherlock_run"
    assert res["target"] == "octocat"
    assert res["target_kind"] == "username"
    assert len(res["accounts"]) == 2
    assert res["call_id"] == "qa-call-id"


def test_sherlock_run_rejects_username_out_of_scope(osint_eng, monkeypatch):
    from mcp_servers.osint_server import sherlock_run

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(sherlock_run(
        engagement_id=osint_eng.id, username="not-in-scope",
    ))
    assert "error" in res
    assert "scope" in res["error"].lower()


def test_holehe_run_rejects_email_out_of_scope(osint_eng, monkeypatch):
    from mcp_servers.osint_server import holehe_run

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(holehe_run(
        engagement_id=osint_eng.id, email="bob@example.com",
    ))
    assert "error" in res
    assert "scope" in res["error"].lower()


def test_holehe_run_happy_path(osint_eng, monkeypatch):
    from mcp_servers.osint_server import holehe_run

    _patch_exe_run(monkeypatch, "[+] github.com\n[+] twitter.com\n")
    res = asyncio.run(holehe_run(
        engagement_id=osint_eng.id, email="alice@example.com",
    ))
    assert "error" not in res
    assert res["target_kind"] == "email"
    assert {a["platform"] for a in res["accounts"]} == {"github.com", "twitter.com"}


def test_h8mail_breaches_extracted(osint_eng, monkeypatch):
    from mcp_servers.osint_server import h8mail_run

    _patch_exe_run(
        monkeypatch,
        "[+] target: alice@example.com\n[+] LinkedIn breach (2012)\n",
    )
    res = asyncio.run(h8mail_run(
        engagement_id=osint_eng.id, email="alice@example.com",
    ))
    assert "error" not in res
    assert res["breaches"] == ["LinkedIn breach (2012)"]


def test_h8mail_rejects_dangerous_config_file(osint_eng, monkeypatch):
    from mcp_servers.osint_server import h8mail_run

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(h8mail_run(
        engagement_id=osint_eng.id,
        email="alice@example.com",
        config_file="/etc/passwd; rm -rf /",
    ))
    assert "error" in res
    assert "forbidden" in res["error"].lower()


def test_recon_ng_rejects_invalid_module_name(osint_eng, monkeypatch):
    from mcp_servers.osint_server import recon_ng_batch

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(recon_ng_batch(
        engagement_id=osint_eng.id,
        target="example.com",
        kind="domain",
        modules="recon/domains-hosts/hackertarget; rm -rf /",
    ))
    assert "error" in res
    assert "invalid module" in res["error"].lower()


def test_recon_ng_domain_uses_infra_scope(osint_eng, monkeypatch):
    """Domain mode should NOT require osint_authorization_ref nor identity scope."""
    from mcp_servers.osint_server import recon_ng_batch

    _patch_exe_run(monkeypatch, "ok\n")
    res = asyncio.run(recon_ng_batch(
        engagement_id=osint_eng.id,
        target="example.com",
        kind="domain",
        modules="recon/domains-hosts/hackertarget",
    ))
    assert "error" not in res, res
    assert res["target_kind"] == "domain"


def test_engagement_without_osint_auth_is_rejected(tmp_paths, monkeypatch):
    """An engagement missing osint_authorization_ref must be refused."""
    from mcp_servers.osint_server import sherlock_run

    create = EngagementCreate(
        name="No OSINT", client="x", tester="qa",
        authorization_ref="ROE-INFRA-1",
        # No osint_authorization_ref. Pydantic still allows identity scope
        # to be set — the runtime gate is what stops the call.
        scope_usernames=["octocat"],
    )
    eng = Engagement(**create.model_dump())

    async def _setup():
        from mcp_servers import osint_server as _osint
        await _osint.store.init()
        await _osint.store.create_engagement(eng)

    asyncio.run(_setup())

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(sherlock_run(
        engagement_id=eng.id, username="octocat",
    ))
    assert "error" in res
    assert "osint authorization" in res["error"].lower()


def test_engagement_without_identity_scope_is_rejected(tmp_paths, monkeypatch):
    from mcp_servers.osint_server import sherlock_run

    create = EngagementCreate(
        name="No identity", client="x", tester="qa",
        authorization_ref="ROE-INFRA-1",
        osint_authorization_ref="ROE-OSINT-1",
        # All identity buckets empty.
    )
    eng = Engagement(**create.model_dump())

    async def _setup():
        from mcp_servers import osint_server as _osint
        await _osint.store.init()
        await _osint.store.create_engagement(eng)

    asyncio.run(_setup())

    _patch_exe_run(monkeypatch, "")
    res = asyncio.run(sherlock_run(
        engagement_id=eng.id, username="octocat",
    ))
    assert "error" in res
    assert "identity scope" in res["error"].lower()
