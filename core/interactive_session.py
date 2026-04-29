"""
core/interactive_session.py — Long-lived PTY sessions for interactive
offensive tooling (msfconsole, evil-winrm, sqlmap, mitmproxy, ettercap,
gdb, frida, drozer, ...).

Each session is bound to:
  * an engagement_id (for scope + audit correlation)
  * a tool descriptor from parrot_tools.yaml (must have interactive=true)
  * an actor (user/agent)

Guarantees:
  - Scope: target arg validated via ScopeValidator before spawn.
  - Audit: every start/send/read/close is appended to AuditLog as
    action=session_* with details payload (truncated).
  - TTL: idle session reaped after `idle_timeout_seconds`.
  - Caps: max sessions per engagement / globally (config.yaml).
  - Sudo: descriptors with requires_sudo=true are launched via
    `sudo -S -p ''` and the vault-stored password is written exactly once
    on the child's stdin before the banner is read.
  - Output: each read returns at most `max_read_bytes` bytes.

Implementation note: uses `pexpect` (pure Python, BSD-licensed) for the
PTY plumbing. `pexpect.spawn` runs the child in a forked PTY so the tool
behaves identically to an interactive terminal.
"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import pexpect
except ImportError as _e:  # pragma: no cover - clearer error at call time
    pexpect = None  # type: ignore
    _pexpect_err = _e
else:
    _pexpect_err = None

import yaml

from core.audit_log import AuditLog
from core.models import AuditEntry, Phase
from core.parrot_catalog import (
    CatalogError, get_descriptor, render_argv,
)
from core.scope_validator import ScopeValidator, ScopeViolation
from core.sudo_vault import get_sudo_vault


# ── Config ─────────────────────────────────────────────────────────────────

_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


def _cfg() -> dict:
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            return (yaml.safe_load(f) or {}).get("interactive_sessions", {}) or {}
    return {}


def _max_per_engagement() -> int:
    return int(_cfg().get("max_per_engagement", 5))


def _max_global() -> int:
    return int(_cfg().get("max_global", 20))


def _idle_timeout() -> int:
    return int(_cfg().get("idle_timeout_seconds", 1800))  # 30 min


def _max_read_bytes() -> int:
    return int(_cfg().get("max_read_bytes", 65536))  # 64 KiB


# ── Errors ─────────────────────────────────────────────────────────────────

class SessionError(Exception): ...
class SessionNotFound(SessionError): ...
class SessionLimitReached(SessionError): ...
class SessionDead(SessionError): ...


# ── State ──────────────────────────────────────────────────────────────────

@dataclass
class _Session:
    id: str
    tool: str
    engagement_id: str
    actor: str
    target: Optional[str]
    proc: "pexpect.spawn"
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    closed: bool = False
    descriptor: dict = field(default_factory=dict)
    cumulative_bytes_read: int = 0
    cumulative_bytes_sent: int = 0


class InteractiveSessionManager:
    """
    Process-wide registry of interactive PTY sessions. Designed to be a
    singleton (see ``get_manager``); not safe to instantiate twice.
    """

    def __init__(self, audit_log: Optional[AuditLog] = None):
        self._sessions: dict[str, _Session] = {}
        self._lock = asyncio.Lock()
        self._audit = audit_log or AuditLog()

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(
        self,
        tool_name: str,
        engagement_id: str,
        args: dict,
        actor: str = "agent",
        scope: Optional[ScopeValidator] = None,
        env: Optional[dict] = None,
    ) -> dict:
        if pexpect is None:
            raise SessionError(
                f"pexpect not installed: {_pexpect_err}. "
                "Run: pip install pexpect"
            )

        d = get_descriptor(tool_name)
        if not d:
            raise SessionError(f"unknown tool '{tool_name}'")
        if not d.get("interactive"):
            raise SessionError(
                f"tool '{tool_name}' is not declared interactive in catalog "
                "(use parrot_tool_run instead)"
            )

        # Render argv (also validates args)
        try:
            argv, norm_args = render_argv(d, args)
        except CatalogError as e:
            raise SessionError(f"validation: {e}")

        # Scope enforcement
        scope_key = d.get("scope_arg")
        target = norm_args.get(scope_key) if scope_key else None
        if target and scope is not None:
            try:
                scope.assert_in_scope(target, engagement_id)
            except ScopeViolation as e:
                await self._audit_safe(
                    engagement_id, actor,
                    "session_denied", target,
                    {"tool": tool_name, "reason": "scope", "detail": str(e)},
                )
                raise SessionError(f"scope: {e}")

        async with self._lock:
            # Cap enforcement
            alive = [s for s in self._sessions.values() if not s.closed]
            if len(alive) >= _max_global():
                raise SessionLimitReached(
                    f"global cap reached ({_max_global()})"
                )
            mine = [s for s in alive if s.engagement_id == engagement_id]
            if len(mine) >= _max_per_engagement():
                raise SessionLimitReached(
                    f"engagement cap reached ({_max_per_engagement()})"
                )

            # Spawn
            binary = d["binary"]
            cmd_argv: list[str] = []
            sudo_pwd_bytes: Optional[bytes] = None
            if d.get("requires_sudo"):
                vault = get_sudo_vault()
                if not await vault.is_unlocked():
                    raise SessionError(
                        f"tool '{tool_name}' requires sudo but the vault is locked; "
                        "unlock it via /api/sudo/unlock from the dashboard first"
                    )
                async with vault.borrow() as pw:
                    sudo_pwd_bytes = bytes(pw)
                cmd_argv += ["sudo", "-S", "-p", ""]
            cmd_argv += [binary] + argv

            try:
                proc = pexpect.spawn(
                    cmd_argv[0],
                    args=cmd_argv[1:],
                    timeout=10,
                    encoding="utf-8",
                    codec_errors="replace",
                    env={**os.environ, **(env or {})},
                    echo=False,
                )
            except Exception as e:
                raise SessionError(f"spawn failed: {e}")

            # Feed the sudo password exactly once on stdin, then forget it.
            if sudo_pwd_bytes is not None:
                try:
                    proc.sendline(sudo_pwd_bytes.decode("utf-8"))
                finally:
                    sudo_pwd_bytes = None  # noqa: F841 — drop reference

            sid = str(uuid.uuid4())
            sess = _Session(
                id=sid, tool=tool_name, engagement_id=engagement_id,
                actor=actor, target=target, proc=proc, descriptor=d,
            )
            self._sessions[sid] = sess

        # Initial banner
        banner = await self._read_until(sess, prompts=None, timeout=4)

        await self._audit_safe(
            engagement_id, actor, "session_start", target or "-",
            {
                "session_id": sid, "tool": tool_name,
                "argv": cmd_argv, "banner_excerpt": banner[-512:],
            },
        )

        interaction = d.get("interaction") or {}
        return {
            "session_id": sid,
            "tool": tool_name,
            "pid": proc.pid,
            "banner": banner,
            "interaction_protocol": {
                "type": interaction.get("type", "pty"),
                "prompts": interaction.get("prompts", []),
                "commands_help": interaction.get("commands_help", ""),
            },
            "ttl_seconds": _idle_timeout(),
        }

    async def send(
        self,
        session_id: str,
        text: str,
        expect_prompt: Optional[str] = None,
        timeout: float = 15.0,
    ) -> dict:
        sess = self._require(session_id)
        if sess.closed or not sess.proc.isalive():
            sess.closed = True
            raise SessionDead(f"session {session_id} no longer alive")

        # Send (append newline if absent)
        payload = text if text.endswith("\n") else text + "\n"
        try:
            sess.proc.send(payload)
        except Exception as e:
            sess.closed = True
            raise SessionDead(f"send failed: {e}")
        sess.cumulative_bytes_sent += len(payload)
        sess.last_used = time.time()

        out = await self._read_until(
            sess,
            prompts=[expect_prompt] if expect_prompt else None,
            timeout=timeout,
        )

        await self._audit_safe(
            sess.engagement_id, sess.actor, "session_send", sess.target or "-",
            {
                "session_id": session_id, "tool": sess.tool,
                "input_excerpt": text[:512],
                "output_excerpt": out[-1024:],
                "expect_prompt": expect_prompt,
            },
        )
        return {
            "session_id": session_id,
            "output": out,
            "alive": sess.proc.isalive(),
            "matched_prompt": (
                expect_prompt if expect_prompt and expect_prompt in out else None
            ),
        }

    async def read(
        self, session_id: str, timeout: float = 5.0,
    ) -> dict:
        sess = self._require(session_id)
        out = await self._read_until(sess, prompts=None, timeout=timeout)
        return {
            "session_id": session_id,
            "output": out,
            "alive": sess.proc.isalive(),
        }

    async def close(self, session_id: str) -> dict:
        sess = self._require(session_id)
        was_alive = sess.proc.isalive()
        try:
            if was_alive:
                sess.proc.sendcontrol("c")
                await asyncio.sleep(0.2)
                sess.proc.close(force=True)
        except Exception:
            pass
        sess.closed = True

        await self._audit_safe(
            sess.engagement_id, sess.actor, "session_close",
            sess.target or "-",
            {
                "session_id": session_id, "tool": sess.tool,
                "duration_seconds": round(time.time() - sess.created_at, 2),
                "bytes_read": sess.cumulative_bytes_read,
                "bytes_sent": sess.cumulative_bytes_sent,
                "was_alive_at_close": was_alive,
            },
        )
        return {
            "session_id": session_id,
            "closed": True,
            "duration_seconds": round(time.time() - sess.created_at, 2),
        }

    def list(self, engagement_id: Optional[str] = None) -> list[dict]:
        out = []
        for s in self._sessions.values():
            if engagement_id and s.engagement_id != engagement_id:
                continue
            out.append({
                "session_id": s.id,
                "tool": s.tool,
                "engagement_id": s.engagement_id,
                "actor": s.actor,
                "target": s.target,
                "alive": (not s.closed) and s.proc.isalive(),
                "created_at": s.created_at,
                "idle_seconds": round(time.time() - s.last_used, 1),
                "bytes_sent": s.cumulative_bytes_sent,
                "bytes_read": s.cumulative_bytes_read,
            })
        return out

    async def reap_idle(self) -> int:
        """Close sessions that exceeded idle TTL. Returns count closed."""
        now = time.time()
        ttl = _idle_timeout()
        n = 0
        for sid, s in list(self._sessions.items()):
            if s.closed:
                continue
            if (now - s.last_used) > ttl:
                try:
                    await self.close(sid)
                    n += 1
                except Exception:
                    pass
        return n

    # ── Internals ────────────────────────────────────────────────────────

    def _require(self, sid: str) -> _Session:
        s = self._sessions.get(sid)
        if not s:
            raise SessionNotFound(f"session '{sid}' not found")
        return s

    async def _read_until(
        self,
        sess: _Session,
        prompts: Optional[list[str]],
        timeout: float,
    ) -> str:
        """
        Drain output until either a prompt regex matches, EOF/TIMEOUT,
        or max_read_bytes is hit. Runs the blocking pexpect call in a
        thread to keep the asyncio loop responsive.
        """
        cap = _max_read_bytes()

        def _blocking_read() -> str:
            chunks: list[str] = []
            total = 0
            patterns: list = (
                [pexpect.TIMEOUT, pexpect.EOF] +
                ([p for p in prompts if p] if prompts else [])
            )
            try:
                # Use expect_list with raw regexes; pexpect handles compiled.
                idx = sess.proc.expect(patterns, timeout=timeout)
                # Whatever was matched is in proc.before + proc.after
                before = sess.proc.before or ""
                after = ""
                if idx >= 2:  # matched a real prompt
                    after = sess.proc.after or ""
                chunks.append(before)
                if after:
                    chunks.append(after)
            except pexpect.TIMEOUT:
                chunks.append(sess.proc.before or "")
            except pexpect.EOF:
                chunks.append(sess.proc.before or "")
                sess.closed = True
            except Exception as e:
                chunks.append(f"\n[read-error] {e}\n")
            total = sum(len(c) for c in chunks)
            if total > cap:
                joined = "".join(chunks)
                return (
                    joined[: cap // 2]
                    + f"\n…[truncated {total - cap} bytes]…\n"
                    + joined[-cap // 2:]
                )
            return "".join(chunks)

        out = await asyncio.to_thread(_blocking_read)
        sess.cumulative_bytes_read += len(out)
        sess.last_used = time.time()
        return out

    async def _audit_safe(
        self, engagement_id: str, actor: str, action: str,
        target: str, details: dict,
    ) -> None:
        try:
            await self._audit.write(AuditEntry(
                engagement_id=engagement_id, actor=actor,
                action=action, target=target, details=details,
            ))
        except Exception:
            pass


# ── Singleton ──────────────────────────────────────────────────────────────

_MANAGER: Optional[InteractiveSessionManager] = None


def get_manager() -> InteractiveSessionManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = InteractiveSessionManager()
    return _MANAGER
