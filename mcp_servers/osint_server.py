"""
mcp_servers/osint_server.py — MCP Server: Person/Identity OSINT.

Phase 8 — exposes 9 OSINT tools that target *identity* (email, username,
person, social handle) rather than network infrastructure.

Hard contract:
  * Every tool requires a non-empty ``Engagement.osint_authorization_ref``
    (separate from ``authorization_ref`` covering infra) → a missing value
    is a fatal "scope" error returned to the caller.
  * The target value MUST appear (after normalization) in the engagement's
    matching ``scope_emails / scope_usernames / scope_persons /
    scope_social_handles`` list. Hard-match semantics — no DNS fallback,
    no wildcard, no soft-allow.
  * Every successful execution writes ``pii=true`` in its audit entry so
    the entries can be filtered/purged for GDPR right-to-erasure.

Design notes:
  * The server is intentionally separate from ``recon_server.py`` to keep
    the PII surface auditable in isolation and disable-able per engagement.
  * It mutates the shared ``ToolExecutor._scope`` attribute in the same
    way recon_server does. This is NOT thread-safe under concurrent calls
    on the SAME executor instance — known limitation tracked separately;
    tests rely on serial execution.
  * Output schemas are unified across tools:
        {tool, target, target_kind, accounts: [...], emails_found: [...],
         breaches: [...], raw, command, duration_seconds, exit_code, ...}
"""
import asyncio
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP

from core.audit_log import AuditLog
from core.executor import SecurityError, ToolExecutor
from core.models import Engagement, Phase
from core.scope_validator import IdentityKind, ScopeValidator, ScopeViolation
from core.session_store import SessionStore
from core.tool_output_store import get_tool_output_store
from mcp_servers._response import register_resource_handlers


# ── Singletons ───────────────────────────────────────────────────────────────

_db_path  = os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db")
_log_path = os.environ.get("AUDIT_LOG_PATH",  "./logs/audit.jsonl")

store = SessionStore(_db_path)
audit = AuditLog(_log_path)
_exe  = ToolExecutor(audit_log=audit)

mcp = FastMCP("pentest-osint")
register_resource_handlers(mcp, get_tool_output_store, server_suffix="osint")

# Per-engagement lock around shared `_exe._scope` mutation.
_scope_locks: dict[str, asyncio.Lock] = {}


def _scope_lock(engagement_id: str) -> asyncio.Lock:
    lk = _scope_locks.get(engagement_id)
    if lk is None:
        lk = asyncio.Lock()
        _scope_locks[engagement_id] = lk
    return lk


def _require_binary(binary: str, install_hint: str = "") -> Optional[dict]:
    """Return a structured ``setup_required`` error if *binary* is missing.

    Returns ``None`` when the binary resolves on PATH — callers proceed
    with execution. Set ``SAP_OSINT_SKIP_BINARY_CHECK=1`` to bypass (used
    by unit tests that monkeypatch ``ToolExecutor.run``).
    """
    if os.environ.get("SAP_OSINT_SKIP_BINARY_CHECK", "").lower() in ("1", "true", "yes"):
        return None
    if shutil.which(binary):
        return None
    return {
        "error": "setup_required",
        "missing_binary": binary,
        "install_cmd": install_hint or (
            f"bash scripts/install_missing_tools.sh  # install '{binary}'"
        ),
        "hint": (
            f"binary '{binary}' is not installed on this host; install it "
            "or pick another available osint tool before retrying."
        ),
    }


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _load_authorized_engagement(engagement_id: str) -> tuple[Optional[Engagement], Optional[ScopeValidator], Optional[dict]]:
    """Load the engagement, build a ScopeValidator and verify OSINT auth.

    Returns ``(engagement, scope, error_dict)``. On any failure, the first
    two values are None and ``error_dict`` is the dict to return to the
    caller. On success, ``error_dict`` is None.
    """
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if eng is None:
        return None, None, {"error": f"engagement '{engagement_id}' not found"}
    if not (eng.osint_authorization_ref or "").strip():
        return None, None, {
            "error": (
                "OSINT authorization missing: engagement "
                f"'{engagement_id}' has no osint_authorization_ref. "
                "Person/identity OSINT requires a separate ROE reference."
            )
        }
    scope = ScopeValidator(
        cidrs=eng.scope_cidrs, domains=eng.scope_domains, urls=eng.scope_urls,
        emails=eng.scope_emails, usernames=eng.scope_usernames,
        persons=eng.scope_persons, social_handles=eng.scope_social_handles,
        engagement_id=engagement_id,
    )
    if not scope.has_identity_scope:
        return None, None, {
            "error": (
                f"engagement '{engagement_id}' has no identity scope "
                "(scope_emails / scope_usernames / scope_persons / "
                "scope_social_handles all empty)."
            )
        }
    return eng, scope, None


async def _run_identity_tool(
    *,
    binary: str,
    argv: list[str],
    engagement_id: str,
    target: str,
    kind: IdentityKind,
    timeout: int,
    install_hint: str = "",
) -> dict:
    """Common executor wrapper. Returns ``{error: str}`` on any failure."""
    eng, scope, err = await _load_authorized_engagement(engagement_id)
    if err is not None:
        return err

    setup_err = _require_binary(binary, install_hint)
    if setup_err is not None:
        return setup_err

    async with _scope_lock(engagement_id):
        _exe._scope = scope
        try:
            try:
                result = await _exe.run(
                    tool=binary,
                    args=argv,
                    engagement_id=engagement_id,
                    phase=Phase.RECON,
                    timeout=timeout,
                    identity_target=(target, kind.value),
                    pii=True,
                )
            except ScopeViolation as exc:
                return {"error": f"scope: {exc}"}
            except SecurityError as exc:
                return {"error": f"security: {exc}"}
            except FileNotFoundError as exc:
                return {
                    "error": "setup_required",
                    "missing_binary": binary,
                    "install_cmd": install_hint
                    or f"bash scripts/install_missing_tools.sh  # install '{binary}'",
                    "hint": str(exc),
                }
        finally:
            _exe._scope = None

    return {
        "command": result.command,
        "exit_code": result.returncode,
        "duration_seconds": result.duration_seconds,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "call_id": result.call_id,
        "truncated_in_memory": bool(result.truncated),
    }


# ── Output parsers ──────────────────────────────────────────────────────────
# All parsers are best-effort and tolerant of malformed input. They return
# a list of ``{platform, url}`` accounts when applicable.

_SHERLOCK_LINE = re.compile(r"^\[\+\]\s+(?P<platform>[^:]+):\s+(?P<url>https?://\S+)\s*$")


def _parse_sherlock(stdout: str) -> list[dict]:
    accounts: list[dict] = []
    for line in stdout.splitlines():
        m = _SHERLOCK_LINE.match(line.strip())
        if m:
            accounts.append({"platform": m.group("platform").strip(),
                             "url": m.group("url").strip(),
                             "confidence": "high"})
    return accounts


_HOLEHE_LINE = re.compile(r"^\[\+\]\s+(?P<platform>\S+)\s*$")


def _parse_holehe(stdout: str) -> list[dict]:
    accounts: list[dict] = []
    for line in stdout.splitlines():
        m = _HOLEHE_LINE.match(line.strip())
        if m:
            accounts.append({"platform": m.group("platform"), "url": "",
                             "confidence": "medium"})
    return accounts


_MAIGRET_LINE = re.compile(r"^\[\+\]\s+(?P<platform>[^:]+):\s+(?P<url>https?://\S+)")


def _parse_maigret(stdout: str) -> list[dict]:
    accounts: list[dict] = []
    for line in stdout.splitlines():
        m = _MAIGRET_LINE.search(line.strip())
        if m:
            accounts.append({"platform": m.group("platform").strip(),
                             "url": m.group("url").strip(),
                             "confidence": "medium"})
    return accounts


def _parse_h8mail(stdout: str) -> dict:
    """h8mail prints a table; we extract simple breach indicators."""
    breaches: list[str] = []
    for line in stdout.splitlines():
        s = line.strip()
        if "[+]" in s and ("breach" in s.lower() or "leak" in s.lower()):
            breaches.append(s.lstrip("[+]").strip())
    return {"breaches": breaches}


def _parse_json_safe(stdout: str) -> Optional[dict | list]:
    """Try to parse stdout as JSON (whole or first JSON line)."""
    s = stdout.strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # try line-by-line for tools that emit ndjson + log noise
        for line in s.splitlines():
            line = line.strip()
            if line.startswith(("{", "[")):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
    return None


def _kind_to_scope_field(kind: str) -> str:
    return {"email": "emails", "username": "usernames",
            "person": "persons", "social_handle": "social_handles"}[kind]


# ── Tool: sherlock ──────────────────────────────────────────────────────────

@mcp.tool()
async def sherlock_run(
    engagement_id: str,
    username: str,
    timeout: int = 10,
) -> dict:
    """
    Find an authorized username across ~400 social networks (passive).

    Args:
        engagement_id: must have ``osint_authorization_ref`` and the
                       username present in ``scope_usernames``.
        username:      the target identifier (case-insensitive).
        timeout:       per-site request timeout (seconds).

    Returns:
        dict with ``accounts: [{platform, url, confidence}]`` plus the
        canonical execution metadata.
    """
    res = await _run_identity_tool(
        binary="sherlock",
        argv=["--print-found", "--no-color", "--timeout", str(int(timeout)), username],
        engagement_id=engagement_id, target=username,
        kind=IdentityKind.USERNAME, timeout=900,
    )
    if "error" in res:
        return res
    res.update({
        "tool": "sherlock_run",
        "target": username, "target_kind": "username",
        "accounts": _parse_sherlock(res["stdout"]),
    })
    return res


# ── Tool: maigret ───────────────────────────────────────────────────────────

@mcp.tool()
async def maigret_run(
    engagement_id: str,
    username: str,
    timeout: int = 30,
) -> dict:
    """Deep username OSINT (3000+ sites). Slower than sherlock."""
    res = await _run_identity_tool(
        binary="maigret",
        argv=["--no-color", "--timeout", str(int(timeout)), username],
        engagement_id=engagement_id, target=username,
        kind=IdentityKind.USERNAME, timeout=1800,
    )
    if "error" in res:
        return res
    res.update({
        "tool": "maigret_run",
        "target": username, "target_kind": "username",
        "accounts": _parse_maigret(res["stdout"]),
    })
    return res


# ── Tool: holehe ────────────────────────────────────────────────────────────

@mcp.tool()
async def holehe_run(
    engagement_id: str,
    email: str,
) -> dict:
    """Discover SaaS accounts registered against an authorized email."""
    res = await _run_identity_tool(
        binary="holehe",
        argv=["--only-used", "--no-color", email],
        engagement_id=engagement_id, target=email,
        kind=IdentityKind.EMAIL, timeout=600,
    )
    if "error" in res:
        return res
    res.update({
        "tool": "holehe_run",
        "target": email, "target_kind": "email",
        "accounts": _parse_holehe(res["stdout"]),
    })
    return res


# ── Tool: h8mail ────────────────────────────────────────────────────────────

@mcp.tool()
async def h8mail_run(
    engagement_id: str,
    email: str,
    config_file: str = "",
) -> dict:
    """Email breach hunting via free public sources (HIBP scraper, Scylla).

    ``config_file`` is optional and may point to a YAML with paid API keys.
    Without it h8mail uses only free sources.
    """
    argv = ["-t", email]
    if config_file:
        # Refuse paths with shell metas; the executor will also re-check.
        if any(c in config_file for c in (";", "|", "&", "$", "`", "\n", " ")):
            return {"error": "config_file contains forbidden characters"}
        argv += ["-c", config_file]
    res = await _run_identity_tool(
        binary="h8mail", argv=argv,
        engagement_id=engagement_id, target=email,
        kind=IdentityKind.EMAIL, timeout=600,
    )
    if "error" in res:
        return res
    parsed = _parse_h8mail(res["stdout"])
    res.update({
        "tool": "h8mail_run",
        "target": email, "target_kind": "email",
        "breaches": parsed["breaches"],
    })
    return res


# ── Tool: whatsmyname ───────────────────────────────────────────────────────

@mcp.tool()
async def whatsmyname_run(
    engagement_id: str,
    username: str,
) -> dict:
    """Username enumeration using the WhatsMyName social-account dataset."""
    res = await _run_identity_tool(
        binary="whatsmyname",
        argv=["-u", username],
        engagement_id=engagement_id, target=username,
        kind=IdentityKind.USERNAME, timeout=600,
    )
    if "error" in res:
        return res
    # WhatsMyName CLIs vary; prefer JSON if present, else passthrough.
    parsed = _parse_json_safe(res["stdout"])
    accounts: list[dict] = []
    if isinstance(parsed, list):
        for entry in parsed:
            if isinstance(entry, dict) and entry.get("url"):
                accounts.append({
                    "platform": entry.get("name", entry.get("site", "?")),
                    "url": entry["url"], "confidence": "medium",
                })
    res.update({
        "tool": "whatsmyname_run",
        "target": username, "target_kind": "username",
        "accounts": accounts,
    })
    return res


# ── Tool: social-analyzer ──────────────────────────────────────────────────

@mcp.tool()
async def social_analyzer_run(
    engagement_id: str,
    username: str,
    top: int = 100,
) -> dict:
    """Search and analyze a username across social media (top-N sites)."""
    res = await _run_identity_tool(
        binary="social-analyzer",
        argv=["--cli", "--username", username, "--top", str(int(top)),
              "--output", "json", "--silent"],
        engagement_id=engagement_id, target=username,
        kind=IdentityKind.USERNAME, timeout=900,
    )
    if "error" in res:
        return res
    parsed = _parse_json_safe(res["stdout"])
    accounts: list[dict] = []
    if isinstance(parsed, dict):
        # social-analyzer returns {"detected": [...]}
        detected = parsed.get("detected") or []
        for entry in detected:
            if isinstance(entry, dict):
                accounts.append({
                    "platform": entry.get("title") or entry.get("type", "?"),
                    "url": entry.get("link", ""),
                    "confidence": str(entry.get("rate", "")),
                })
    res.update({
        "tool": "social_analyzer_run",
        "target": username, "target_kind": "username",
        "accounts": accounts,
    })
    return res


# ── Tool: ghunt (email → Google account) ───────────────────────────────────

@mcp.tool()
async def ghunt_email(
    engagement_id: str,
    email: str,
) -> dict:
    """GHunt: extract Google account intel (Gaia ID, profile) from an email.

    REQUIRES one-time cookie setup via ``ghunt login``. The tool fails with
    a clear error if the cookie store is missing.
    """
    res = await _run_identity_tool(
        binary="ghunt",
        argv=["email", email, "--json", "/dev/stdout"],
        engagement_id=engagement_id, target=email,
        kind=IdentityKind.EMAIL, timeout=600,
    )
    if "error" in res:
        return res
    parsed = _parse_json_safe(res["stdout"])
    res.update({
        "tool": "ghunt_email",
        "target": email, "target_kind": "email",
        "google_profile": parsed if isinstance(parsed, dict) else None,
    })
    if not parsed and ("creds" in (res.get("stderr") or "").lower()
                       or "login" in (res.get("stderr") or "").lower()):
        res["setup_required"] = (
            "Run `ghunt login` to populate ~/.malfrats/ghunt/ before retrying."
        )
    return res


# ── Tool: recon-ng (batch passive workspace) ───────────────────────────────

_RECON_NG_KIND_TO_FIELD = {
    # recon-ng database column for each kind we accept
    "domain": "domains.domain",
    "email": "contacts.email",
    "person": "profiles.username",
    "username": "profiles.username",
}


def _build_recon_ng_resource(target: str, kind: str, modules: list[str]) -> str:
    """Render a resource-script that adds the target and runs each module."""
    field = _RECON_NG_KIND_TO_FIELD[kind]
    table = field.split(".")[0]
    column = field.split(".")[1]
    lines = [
        f"db insert {table} {column}~{target}",
    ]
    for m in modules:
        lines += [
            f"modules load {m}",
            "run",
            "back",
        ]
    lines.append("exit")
    return "\n".join(lines) + "\n"


@mcp.tool()
async def recon_ng_batch(
    engagement_id: str,
    target: str,
    kind: str = "domain",
    modules: str = "recon/domains-hosts/hackertarget",
) -> dict:
    """Run recon-ng with a curated module set against an authorized target.

    ``kind`` controls which identity bucket is checked: domain (uses infra
    scope), email/person/username (use identity scope).
    Modules are comma-separated; pass only PASSIVE modules for safety.
    """
    if kind not in _RECON_NG_KIND_TO_FIELD:
        return {"error": f"unsupported kind '{kind}'"}

    eng, scope, err = await _load_authorized_engagement(engagement_id)
    if err is not None and kind != "domain":
        return err
    # Domain mode reuses infra scope and does NOT require osint_auth_ref;
    # but we still go through this server only for the curated module set.
    if kind == "domain":
        await store.init()
        eng = await store.get_engagement(engagement_id)
        if eng is None:
            return {"error": f"engagement '{engagement_id}' not found"}
        scope = ScopeValidator(
            cidrs=eng.scope_cidrs, domains=eng.scope_domains, urls=eng.scope_urls,
            engagement_id=engagement_id,
        )

    # Scope check (manual: kind drives which validator path we use)
    try:
        if kind == "domain":
            scope.assert_in_scope(target, engagement_id)
        else:
            scope.assert_identity_in_scope(target, kind, engagement_id)
    except ScopeViolation as exc:
        return {"error": f"scope: {exc}"}

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    if not module_list:
        return {"error": "modules: at least one module required"}

    # Reject obvious shell metacharacters in module names (defensive — they
    # flow into the resource script unmodified).
    for m in module_list:
        if not re.match(r"^[a-zA-Z0-9_./-]+$", m):
            return {"error": f"invalid module name: {m!r}"}

    resource_text = _build_recon_ng_resource(target, kind, module_list)
    fd, resource_path = tempfile.mkstemp(prefix="reconng_", suffix=".rc")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(resource_text)
        _exe._scope = scope
        try:
            try:
                result = await _exe.run(
                    tool="recon-ng",
                    args=["-r", resource_path],
                    engagement_id=engagement_id,
                    phase=Phase.RECON,
                    timeout=900,
                    # We've already checked scope above; do NOT pass
                    # target/identity_target to avoid double-validation
                    # against an inappropriate path.
                    pii=(kind != "domain"),
                )
            except SecurityError as exc:
                return {"error": f"security: {exc}"}
        finally:
            _exe._scope = None
    finally:
        try:
            os.unlink(resource_path)
        except OSError:
            pass

    # Detect logical failure: recon-ng emits `[!] Invalid …` lines while
    # exiting 0. Surface this as success=false with parse_warnings so the
    # caller doesn't treat the run as a clean success.
    parse_warnings = [
        ln.strip()
        for ln in result.stdout.splitlines()
        if ln.lstrip().startswith("[!]") and "invalid" in ln.lower()
    ]
    success = result.returncode == 0 and not parse_warnings

    return {
        "tool": "recon_ng_batch",
        "target": target, "target_kind": kind,
        "modules": module_list,
        "success": success,
        "parse_warnings": parse_warnings,
        "command": result.command,
        "exit_code": result.returncode,
        "duration_seconds": result.duration_seconds,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "call_id": result.call_id,
    }


# ── Tool: spiderfoot (CLI batch) ───────────────────────────────────────────

@mcp.tool()
async def spiderfoot_batch(
    engagement_id: str,
    target: str,
    kind: str = "email",
    modules: str = "sfp_dnsresolve,sfp_email,sfp_hunter,sfp_haveibeenpwned",
) -> dict:
    """Run a SpiderFoot CLI scan with a curated PASSIVE module set.

    ``kind`` selects the scope path: domain → infra; email/person/username
    → identity scope (requires ``osint_authorization_ref``).
    """
    if kind not in ("domain", "email", "person", "username"):
        return {"error": f"unsupported kind '{kind}'"}

    if kind == "domain":
        await store.init()
        eng = await store.get_engagement(engagement_id)
        if eng is None:
            return {"error": f"engagement '{engagement_id}' not found"}
        scope = ScopeValidator(
            cidrs=eng.scope_cidrs, domains=eng.scope_domains,
            urls=eng.scope_urls, engagement_id=engagement_id,
        )
        try:
            scope.assert_in_scope(target, engagement_id)
        except ScopeViolation as exc:
            return {"error": f"scope: {exc}"}
        identity_target = None
    else:
        eng, scope, err = await _load_authorized_engagement(engagement_id)
        if err is not None:
            return err
        try:
            scope.assert_identity_in_scope(target, kind, engagement_id)
        except ScopeViolation as exc:
            return {"error": f"scope: {exc}"}
        identity_target = (target, kind)

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    for m in module_list:
        if not re.match(r"^[a-zA-Z0-9_]+$", m):
            return {"error": f"invalid module name: {m!r}"}

    _exe._scope = scope
    try:
        try:
            result = await _exe.run(
                tool="sf",
                args=["-s", target, "-m", ",".join(module_list),
                      "-F", "json", "-q"],
                engagement_id=engagement_id,
                phase=Phase.RECON,
                timeout=1800,
                identity_target=identity_target,
                pii=(identity_target is not None),
            )
        except ScopeViolation as exc:
            return {"error": f"scope: {exc}"}
        except SecurityError as exc:
            return {"error": f"security: {exc}"}
    finally:
        _exe._scope = None

    parsed = _parse_json_safe(result.stdout)
    return {
        "tool": "spiderfoot_batch",
        "target": target, "target_kind": kind,
        "modules": module_list,
        "command": result.command,
        "exit_code": result.returncode,
        "duration_seconds": result.duration_seconds,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "events": parsed if isinstance(parsed, list) else None,
        "call_id": result.call_id,
    }


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
