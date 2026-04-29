"""
mcp_servers/parrot_server.py — Generic MCP server backed by ``parrot_tools.yaml``.

Exposes three tools to the LLM:

  * parrot_list_tools     — list every tool in the catalogue (name, category,
                            availability, sudo flag).
  * parrot_tool_describe  — return the full descriptor for one tool.
  * parrot_tool_run       — validate args, render argv, dispatch via
                            ToolExecutor (scope + sudo + audit enforced).

This server is the bridge between the declarative catalogue and the agent.
It complements the specialised servers (recon / exploit / blueteam) that
expose first-class tools with deeper output parsing.
"""
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP

from core.audit_log import AuditLog
from core.executor import ToolExecutor, SecurityError
from core.interactive_session import (
    SessionError, SessionLimitReached, SessionNotFound, get_manager,
)
from core.models import AuditEntry, Phase
from core.parrot_catalog import (
    CatalogError, auto_artifact_flags, binary_available, descriptor_doc,
    gap_report, get_descriptor, list_by_category, list_names, load_catalog,
    materialize_artifact_flags, render_argv, response_profile_for,
)
from core.scope_validator import IdentityKind, ScopeValidator, ScopeViolation
from core.session_store import SessionStore
from core.sudo_vault import SudoLocked
from core.tool_output_store import get_tool_output_store
from mcp_servers._response import build_tool_response, register_resource_handlers


# ── Singletons ───────────────────────────────────────────────────────────────

_db_path  = os.environ.get("SESSION_DB_PATH", "./sessions/assessments.db")
_log_path = os.environ.get("AUDIT_LOG_PATH",  "./logs/audit.jsonl")

store = SessionStore(_db_path)
audit = AuditLog(_log_path)
_exe  = ToolExecutor(audit_log=audit)

mcp = FastMCP("pentest-parrot")
register_resource_handlers(mcp, get_tool_output_store, server_suffix="parrot")

# Per-engagement lock around `_exe._scope` mutation. Prevents the documented
# race when concurrent MCP HTTP calls target the same shared executor.
_scope_locks: dict[str, asyncio.Lock] = {}


def _scope_lock(engagement_id: str) -> asyncio.Lock:
    lk = _scope_locks.get(engagement_id)
    if lk is None:
        lk = asyncio.Lock()
        _scope_locks[engagement_id] = lk
    return lk


# Map osint descriptor.scope_arg → IdentityKind
_SCOPE_ARG_TO_IDENTITY_KIND: dict[str, IdentityKind] = {
    "email": IdentityKind.EMAIL,
    "username": IdentityKind.USERNAME,
    "person": IdentityKind.PERSON,
    "social_handle": IdentityKind.SOCIAL_HANDLE,
    "handle": IdentityKind.SOCIAL_HANDLE,
}


# ── Helpers ─────────────────────────────────────────────────────────

async def _scope_for(engagement_id: str) -> tuple[Optional[ScopeValidator], Optional[object]]:
    """Return ``(scope, engagement)`` or ``(None, None)`` if unknown.

    The engagement is returned alongside the scope so callers can inspect
    ``osint_authorization_ref`` without a second DB roundtrip.
    """
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        return None, None
    scope = ScopeValidator(
        cidrs=eng.scope_cidrs, domains=eng.scope_domains, urls=eng.scope_urls,
        emails=eng.scope_emails, usernames=eng.scope_usernames,
        persons=eng.scope_persons, social_handles=eng.scope_social_handles,
        engagement_id=engagement_id,
    )
    return scope, eng


def _summary_view(d: dict) -> dict:
    return {
        "name": d.get("name"),
        "category": d.get("category"),
        "description": d.get("description", "")[:200],
        "binary": d.get("binary"),
        "requires_sudo": bool(d.get("requires_sudo")),
        "available": binary_available(d.get("binary", d.get("name", ""))),
        "interactive": bool(d.get("interactive")),
        "risk_level": d.get("risk_level", "unknown"),
        "when": (d.get("when") or "")[:160],
    }


# ── MCP Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
async def parrot_list_tools(category: str = "", available_only: bool = True) -> dict:
    """
    List every tool in the Parrot catalogue. Filter by category if provided.

    Categories include: recon, web, vuln, ad, creds, network, wireless, re,
    secrets, osint.

    Args:
        category: optional category filter.
        available_only: when True (default) only tools whose binary is
            installed are returned. Set to False to inspect the full
            catalogue including missing tools.
    """
    cat = load_catalog()
    rows = [_summary_view(d) for d in cat]
    if category:
        rows = [r for r in rows if r["category"] == category]
    if available_only:
        rows = [r for r in rows if r["available"]]
    return {
        "count": len(rows),
        "available_only": available_only,
        "by_category": list_by_category(),
        "tools": rows,
        "gap": gap_report(),
    }


@mcp.tool()
async def parrot_tool_describe(name: str) -> dict:
    """Return the full descriptor of one catalogue tool."""
    d = get_descriptor(name)
    if not d:
        return {"error": f"unknown tool '{name}'", "available": list_names()[:50]}
    return {
        **d,
        "available": binary_available(d.get("binary", name)),
        "doc_markdown": descriptor_doc(d),
    }


@mcp.tool()
async def parrot_tool_run(
    name: str,
    engagement_id: str,
    args_json: str = "{}",
    phase: str = "scanning",
    timeout_seconds: int = 0,
) -> dict:
    """
    Validate args, render argv, and execute a catalogue tool.

    Inputs:
      name            — descriptor name (see parrot_list_tools)
      engagement_id   — required for scope enforcement & audit
      args_json       — JSON object string matching descriptor.args_schema
      phase           — PTES phase string (defaults to scanning)
      timeout_seconds — override descriptor default (0 = use default)
    """
    d = get_descriptor(name)
    if not d:
        return {"error": f"unknown tool '{name}'"}

    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as e:
        return {"error": f"args_json: invalid JSON: {e}"}
    if not isinstance(args, dict):
        return {"error": "args_json must encode a JSON object"}

    # Render & validate
    try:
        argv, norm_args = render_argv(d, args)
    except CatalogError as e:
        return {"error": f"validation: {e}"}

    # Scope enforcement using descriptor.scope_arg.
    # OSINT/PII tools follow the identity-scope path; everything else
    # uses the infra (CIDR/domain/URL) scope.
    scope_key = d.get("scope_arg")
    target = norm_args.get(scope_key) if scope_key else None
    scope, eng = await _scope_for(engagement_id)
    if scope is None:
        return {"error": f"engagement '{engagement_id}' not found"}

    is_osint = (d.get("category") == "osint") or bool(d.get("pii"))
    identity_kind: Optional[IdentityKind] = None
    if is_osint:
        if not (eng.osint_authorization_ref or "").strip():
            return {"error": (
                "OSINT authorization missing: engagement "
                f"'{engagement_id}' has no osint_authorization_ref. "
                "Person/identity OSINT requires a separate ROE reference "
                "(update_engagement osint_authorization_ref=...)."
            )}
        identity_kind = _SCOPE_ARG_TO_IDENTITY_KIND.get(scope_key or "")
        if identity_kind is None:
            return {"error": (
                f"osint tool '{name}' has scope_arg='{scope_key}' which is "
                "not a valid identity kind (email|username|person|social_handle)."
            )}
        if target:
            try:
                scope.assert_identity_in_scope(target, identity_kind, engagement_id)
            except ScopeViolation as e:
                return {"error": f"scope: {e}"}
    elif target:
        try:
            scope.assert_in_scope(target, engagement_id)
        except ScopeViolation as e:
            return {"error": f"scope: {e}"}

    # Phase
    try:
        ph = Phase(phase)
    except Exception:
        ph = Phase.SCANNING

    # Timeout
    timeout = timeout_seconds or int(d.get("default_timeout_seconds", 300))

    # Pre-flight binary availability — surface a structured setup_required
    # error rather than letting FileNotFoundError escape from the executor.
    if not binary_available(d.get("binary", name)):
        return {
            "error": "setup_required",
            "missing_binary": d.get("binary", name),
            "install_via": d.get("install_via", ""),
            "install_cmd": (
                f"bash scripts/install_missing_tools.sh {name}"
            ),
            "hint": (
                f"binary '{d.get('binary', name)}' is not installed; "
                "install it (or pick another available tool) before retrying."
            ),
        }

    # Pre-allocate the ToolOutputStore call directory so we can inject
    # auto-artifact flags (-oA, --output-dir, …) pointing at it BEFORE the
    # process runs. The executor will reuse the same call_id when persisting.
    pre_call_id: Optional[str] = None
    run_id = _exe._run_id  # type: ignore[attr-defined]
    if run_id:
        try:
            store_ = get_tool_output_store()
            pre_call_id, adir = store_.allocate(run_id)
            extra = auto_artifact_flags(d["binary"], argv)
            if extra:
                argv = argv + materialize_artifact_flags(extra, str(adir))
        except Exception:
            # Allocation/injection must never block execution.
            pre_call_id = None

    # Wire scope into executor for the duration of the call (lock-protected
    # to avoid races between concurrent calls on the same engagement).
    async with _scope_lock(engagement_id):
        _exe._scope = scope
        try:
            try:
                run_kwargs: dict = dict(
                    tool=d["binary"],
                    args=argv,
                    engagement_id=engagement_id,
                    phase=ph,
                    timeout=timeout,
                    requires_sudo=bool(d.get("requires_sudo")),
                    sudo_reason=d.get("sudo_reason", ""),
                    call_id=pre_call_id,
                )
                if is_osint and identity_kind is not None and target:
                    run_kwargs["identity_target"] = (target, identity_kind.value)
                    run_kwargs["pii"] = True
                else:
                    run_kwargs["target"] = target
                result = await _exe.run(**run_kwargs)
            except ScopeViolation as e:
                return {"error": f"scope: {e}"}
            except SecurityError as e:
                return {"error": f"security: {e}"}
            except SudoLocked as e:
                return {"error": f"sudo: {e}"}
            except FileNotFoundError as e:
                return {
                    "error": "setup_required",
                    "missing_binary": d.get("binary", name),
                    "install_cmd": f"bash scripts/install_missing_tools.sh {name}",
                    "hint": str(e),
                }
        finally:
            _exe._scope = None

    profile = response_profile_for(d)
    return build_tool_response(
        result,
        summary={
            "tool": name,
            "binary": d["binary"],
            "parser": d.get("parser", "raw"),
            "mitre": d.get("mitre", []),
        },
        profile=profile["profile"],
        head_bytes=profile["head_bytes"],
        tail_bytes=profile["tail_bytes"],
    )


# ── Interactive sessions ─────────────────────────────────────────────────────

@mcp.tool()
async def parrot_session_start(
    name: str,
    engagement_id: str,
    args_json: str = "{}",
    phase: str = "exploitation",
) -> dict:
    """
    Spawn an interactive PTY session for a tool whose descriptor declares
    ``interactive: true`` (e.g. msfconsole, evil-winrm, sqlmap, mitmproxy).

    Returns ``session_id``, the initial banner, and the interaction
    protocol (expected prompts, command help). Use ``parrot_session_send``
    to drive the session and ``parrot_session_close`` to terminate.
    """
    try:
        args = json.loads(args_json) if args_json else {}
    except json.JSONDecodeError as e:
        return {"error": f"args_json: invalid JSON: {e}"}
    if not isinstance(args, dict):
        return {"error": "args_json must encode a JSON object"}

    scope, _eng = await _scope_for(engagement_id)
    if scope is None:
        return {"error": f"engagement '{engagement_id}' not found"}

    mgr = get_manager()
    try:
        return await mgr.start(
            tool_name=name, engagement_id=engagement_id,
            args=args, actor="agent", scope=scope,
        )
    except SessionLimitReached as e:
        return {"error": f"limit: {e}"}
    except SessionError as e:
        return {"error": str(e)}


@mcp.tool()
async def parrot_session_send(
    session_id: str,
    text: str,
    expect_prompt: str = "",
    timeout: float = 15.0,
) -> dict:
    """
    Send ``text`` (a command line) into an interactive session and read the
    output until ``expect_prompt`` matches or ``timeout`` elapses.

    Pass ``expect_prompt=""`` to read for the full timeout window.
    """
    mgr = get_manager()
    try:
        return await mgr.send(
            session_id=session_id, text=text,
            expect_prompt=expect_prompt or None, timeout=timeout,
        )
    except SessionNotFound as e:
        return {"error": f"not_found: {e}"}
    except SessionError as e:
        return {"error": str(e)}


@mcp.tool()
async def parrot_session_close(session_id: str) -> dict:
    """Terminate an interactive session and audit the closure."""
    mgr = get_manager()
    try:
        return await mgr.close(session_id)
    except SessionNotFound as e:
        return {"error": f"not_found: {e}"}
    except SessionError as e:
        return {"error": str(e)}


@mcp.tool()
async def parrot_session_list(engagement_id: str = "") -> dict:
    """List active interactive sessions, optionally filtered by engagement."""
    mgr = get_manager()
    return {"sessions": mgr.list(engagement_id or None)}


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
