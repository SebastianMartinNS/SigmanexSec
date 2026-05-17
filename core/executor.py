"""
core/executor.py — Safe, audited subprocess executor.

Every tool call goes through here. Key guarantees:
  - Allowlist: only pre-approved tools can run
  - Arg sanitization: blocks shell injection patterns
  - Scope check: refuses to run against out-of-scope targets
  - Hard timeout: every subprocess is killed after N seconds
  - Output cap: stdout truncated at MAX_OUTPUT_BYTES
  - Audit: writes an AuditEntry for every execution
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shlex
import time
from pathlib import Path

import yaml

from core.approval_gate import ApprovalGate
from core.models import AuditEntry, ExecutionResult, Phase, ToolOutputRefModel
from core.sudo_vault import SudoLocked, SudoVault, get_sudo_vault
from core.time_utils import utcnow as _sap_utcnow
from core.tool_output_store import ToolOutputStore, get_tool_output_store

# ─────────────────────────────────────────────
# Load config once at import time
# ─────────────────────────────────────────────
_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"
_cfg: dict = {}

def _load_config() -> dict:
    global _cfg
    if not _cfg and _CONFIG_PATH.exists():
        with open(_CONFIG_PATH) as f:
            _cfg = yaml.safe_load(f) or {}
    return _cfg


def _allowed_tools() -> set[str]:
    cfg = _load_config()
    base = set(cfg.get("executor", {}).get("allowed_tools", []))
    extra = set(cfg.get("executor", {}).get("allowed_tools_extra", []))
    blocklist = set(cfg.get("executor", {}).get("allowed_tools_blocklist", []))
    # Also accept every binary declared in the Parrot catalogue.
    try:
        from core.parrot_catalog import list_binaries
        base |= list_binaries()
    except Exception:
        pass
    base |= extra
    base -= blocklist
    # sudo is intentionally NOT on the allowlist for direct exec; it is
    # injected by the executor itself when ``requires_sudo=True``.
    return base


def _blocked_patterns() -> list[str]:
    cfg = _load_config()
    return cfg.get("executor", {}).get("blocked_arg_patterns", [])


# Compile patterns once and cache. We compile lazily on first use so test
# environments that monkey-patch ``_load_config`` keep working, but we also
# expose ``compile_blocked_patterns()`` so that callers (e.g. start-up code,
# tests) can validate the regexes ahead of time and fail loudly on syntax
# errors instead of discovering them at the first matching attempt.
_BLOCKED_PATTERNS_CACHE: list[tuple[str, re.Pattern[str]]] | None = None


def compile_blocked_patterns(force: bool = False) -> list[tuple[str, re.Pattern[str]]]:
    """Compile (and cache) the blocked-arg regexes; raise on syntax errors.

    Call from process startup to fail-closed if config.yaml ships a malformed
    pattern. Without this, a broken regex would silently slip through until
    the first command actually triggers ``_check_args`` — at which point the
    raised :class:`re.error` would surface as a generic 500 to the operator.
    """
    global _BLOCKED_PATTERNS_CACHE
    if _BLOCKED_PATTERNS_CACHE is not None and not force:
        return _BLOCKED_PATTERNS_CACHE
    compiled: list[tuple[str, re.Pattern[str]]] = []
    errors: list[str] = []
    for pat in _blocked_patterns():
        try:
            compiled.append((pat, re.compile(pat, re.IGNORECASE)))
        except re.error as exc:
            errors.append(f"  {pat!r}: {exc}")
    if errors:
        raise ValueError(
            "Invalid blocked_arg_patterns in config.yaml:\n" + "\n".join(errors)
        )
    _BLOCKED_PATTERNS_CACHE = compiled
    return compiled


def _max_output() -> int:
    cfg = _load_config()
    return cfg.get("executor", {}).get("max_output_bytes", 524288)


def _stderr_max_output() -> int:
    """In-memory cap for stderr. Defaults to ``max_output_bytes``.

    The full stderr is always written to the ToolOutputStore; this cap only
    limits the value carried in ``ExecutionResult.stderr`` (LLM context budget).
    """
    cfg = _load_config()
    val = cfg.get("executor", {}).get("stderr_max_output_bytes")
    return int(val) if val is not None else _max_output()


def _persist_max_bytes() -> int:
    """Hard per-stream cap (stdout / stderr) enforced by the executor while
    reading the subprocess. Once the cap is reached we stop appending and
    SIGTERM the process so a runaway tool cannot fill RAM nor disk.

    Default 64 MiB per stream is generous enough for typical nmap/ffuf/sqlmap
    runs but bounds worst-case memory + audit storage growth.
    """
    cfg = _load_config()
    val = cfg.get("executor", {}).get("persist_max_bytes")
    if val is None:
        try:
            val = int(os.environ.get("SAP_EXEC_PERSIST_MAX_BYTES", str(64 * 1024 * 1024)))
        except (TypeError, ValueError):
            val = 64 * 1024 * 1024
    try:
        v = int(val)
    except (TypeError, ValueError):
        return 64 * 1024 * 1024
    return max(v, 1024)


def _persist_outputs() -> bool:
    cfg = _load_config()
    return bool(cfg.get("executor", {}).get("persist_outputs", True))


def _default_timeout() -> int:
    cfg = _load_config()
    return cfg.get("executor", {}).get("default_timeout_seconds", 300)


def _privileged_tools() -> set[str]:
    cfg = _load_config()
    return set(cfg.get("sudo", {}).get("privileged_tools", []))


# ─────────────────────────────────────────────
# Argument-aware privilege detection
# ─────────────────────────────────────────────
# Some tools only need root for *certain* invocations (e.g. nmap raw scans,
# hping3 raw IP, ping with custom intervals). Listing them in
# `sudo.privileged_tools` would force every benign call through sudo.
# Instead we maintain a small map of (tool → predicate(args) → bool).

def _nmap_needs_root(args: list[str]) -> bool:
    """nmap requires root for raw-socket scans and OS detection.
    Reference: nmap(1) — flags requiring CAP_NET_RAW / CAP_NET_ADMIN.
    """
    raw_flags = {
        "-sS", "-sU", "-sO", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX",
        "-sY", "-sZ", "-sI", "-sL", "-PE", "-PP", "-PM", "-PR", "-PO",
        "-O", "--osscan-guess", "--osscan-limit",
        "--traceroute", "--script-args-file",
    }
    for a in args:
        if a in raw_flags:
            return True
        # --send-eth requires raw frames
        if a in ("--send-eth", "--send-ip"):
            return True
    return False


def _hping3_needs_root(args: list[str]) -> bool:
    # hping3 always needs raw sockets unless --udp + non-raw + -E mode
    # which is rare; safer default = True.
    return True


def _ping_needs_root(args: list[str]) -> bool:
    # Default Linux ping is setuid, but custom intervals < 200ms or
    # large packet floods require CAP_NET_RAW.
    for a in args:
        if a in ("-f", "--flood"):
            return True
        if a in ("-i", "--interval"):
            return True
    return False


_ARG_AWARE_PRIVILEGE: dict[str, callable] = {
    "nmap": _nmap_needs_root,
    "hping3": _hping3_needs_root,
    "ping": _ping_needs_root,
}


def _needs_sudo(tool: str, args: list[str]) -> bool:
    """Return True if *tool* with *args* requires sudo elevation.

    Combines the static `sudo.privileged_tools` allowlist (always-needs-root
    binaries like responder/tcpdump) with per-tool argument inspection for
    tools that only sometimes need root (nmap, hping3, ping).
    """
    if not _sudo_enabled():
        return False
    if tool in _privileged_tools():
        return True
    pred = _ARG_AWARE_PRIVILEGE.get(tool)
    if pred is not None:
        try:
            return bool(pred(args))
        except Exception:
            return False
    return False


def _sudo_enabled() -> bool:
    cfg = _load_config()
    return bool(cfg.get("sudo", {}).get("enabled", True))


_SUDO_REDACT_PATTERNS = [
    re.compile(r"(sudo\s+-S\b)[^\n]*", re.IGNORECASE),
]


def redact_sudo(text: str) -> str:
    """Redact any traces of sudo password material from text before logging."""
    if not text:
        return text
    out = text
    for pat in _SUDO_REDACT_PATTERNS:
        out = pat.sub(r"\1 [REDACTED]", out)
    return out


async def _kill_process_tree(proc: asyncio.subprocess.Process, grace: float = 1.5) -> None:
    """SIGTERM the process group, wait briefly, then SIGKILL.

    Used by ``_exec`` on timeout. The child was started with
    ``start_new_session=True`` so its PID is also its PGID — signalling the
    group reaches all descendants (nmap workers, ssh subshells, etc.).
    Falls back to ``proc.kill()`` on platforms without ``killpg``.
    """
    import signal as _signal
    pid = proc.pid
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        pgid = pid
    # Phase 1: gentle SIGTERM to the group.
    try:
        os.killpg(pgid, _signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace)
        return
    except TimeoutError:
        pass
    # Phase 2: hard SIGKILL to the group.
    try:
        os.killpg(pgid, _signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=grace)
    except TimeoutError:
        # Last-resort: process is unkillable (D state). Return; the leader is
        # at least no longer holding the parent coroutine.
        pass


# ─────────────────────────────────────────────
# ToolExecutor
# ─────────────────────────────────────────────

class SecurityError(Exception):
    """Raised when an execution request violates security policy."""


class ToolExecutor:
    """
    Async executor with security enforcement.

    Usage:
        executor = ToolExecutor(audit_log=audit_log, scope_validator=scope)
        result = await executor.run("nmap", ["-sV", "-p", "80,443", "10.0.0.1"],
                                    engagement_id=eid, phase=Phase.SCANNING)
    """

    def __init__(
        self,
        audit_log=None,         # core.audit_log.AuditLog instance
        scope_validator=None,   # core.scope_validator.ScopeValidator instance
        sudo_vault: SudoVault | None = None,
        approval_gate: ApprovalGate | None = None,
        *,
        run_id: str | None = None,
        output_store: ToolOutputStore | None = None,
    ):
        self._audit = audit_log
        self._scope = scope_validator
        self._vault = sudo_vault if sudo_vault is not None else get_sudo_vault()
        self._gate = approval_gate
        self._run_id = run_id or os.environ.get("SAP_RUN_ID", "")
        # Defer store materialization until first use so test fixtures that
        # monkeypatch SAP_SESSIONS_DIR after construction still take effect.
        self._output_store = output_store

    def set_run_id(self, run_id: str) -> None:
        """Bind this executor to a specific run for output persistence."""
        self._run_id = run_id

    def _store(self) -> ToolOutputStore | None:
        if not _persist_outputs():
            return None
        if self._output_store is None:
            self._output_store = get_tool_output_store()
        return self._output_store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        tool: str,
        args: list[str],
        *,
        engagement_id: str = "",
        phase: Phase = Phase.SCANNING,
        timeout: int | None = None,
        cwd: str | None = None,
        target: str | None = None,   # for scope check
        identity_target: tuple[str, str] | None = None,  # (value, kind) for OSINT
        requires_sudo: bool | None = None,
        sudo_reason: str = "",
        call_id: str | None = None,
        pii: bool = False,
        sandbox_profile: str | None = None,
        sandbox_category: str | None = None,
    ) -> ExecutionResult:
        """
        Execute *tool* with *args* after performing all security checks.
        Returns an ExecutionResult regardless of exit code.
        Raises SecurityError if any check fails.

        ``identity_target`` (Phase 8 — person-OSINT) is mutually exclusive
        with ``target`` and triggers ``ScopeValidator.assert_identity_in_scope``
        instead of the infra ``assert_in_scope``. ``pii=True`` flags the audit
        entry so the entry can be filtered/purged for GDPR compliance.
        """
        timeout = timeout or _default_timeout()

        # 1. Validate tool is on the allowlist
        self._check_tool(tool)

        # 2. Sanitize arguments
        self._check_args(args)

        # 3. Scope check (optional but enforced when scope_validator is set).
        #    target and identity_target are mutually exclusive — a single
        #    invocation cannot mix infra and identity targets.
        if target and identity_target:
            raise SecurityError(
                "executor.run(): 'target' and 'identity_target' are mutually exclusive"
            )
        if target and self._scope:
            self._scope.assert_in_scope(target, engagement_id)
        if identity_target and self._scope:
            id_value, id_kind = identity_target
            self._scope.assert_identity_in_scope(id_value, id_kind, engagement_id)
            pii = True  # any identity target implies PII handling

        # 4. Determine if this invocation needs sudo
        if requires_sudo is None:
            requires_sudo = _needs_sudo(tool, args)

        sudo_password: bytes | None = None
        if requires_sudo:
            sudo_password = await self._acquire_sudo(
                tool=tool, args=args, engagement_id=engagement_id,
                sudo_reason=sudo_reason or "privileged tool",
            )

        # 5. Build command and (optionally) wrap it in the OS-level sandbox.
        #    The sandbox is the second line of defence after scope_validator:
        #    it constrains *how* the tool behaves once launched (filesystem,
        #    capabilities, namespaces, network) per a per-category profile
        #    (deploy/sandbox/profiles/<name>.json).
        #
        #    v2.3 limitation: tools that require sudo run UNwrapped. The
        #    bwrap user-namespace strips setuid, so `sudo` would refuse;
        #    a privileged-sandbox proxy is on the v2.4 roadmap.
        from core import sandbox as _sandbox

        sandbox_decision: _sandbox.SandboxDecision | None = None
        if requires_sudo:
            cmd = ["sudo", "-S", "-p", ""] + [tool] + args
        else:
            tool_argv = [tool] + args
            profile_name = _sandbox.resolve_profile(
                sandbox_profile, category_hint=sandbox_category
            )
            sandbox_decision = _sandbox.wrap(
                profile_name, tool_argv, run_id=self._run_id
            )
            cmd = sandbox_decision.wrapped_argv

        # 6. Audit before execution (redacted command for privileged tools).
        #    For sandbox=warn we also emit the would-have-wrapped argv so
        #    operators can verify the profile matches expectations before
        #    flipping to enforce.
        audit_cmd = redact_sudo(shlex.join(cmd)) if requires_sudo else shlex.join(cmd)
        if (
            sandbox_decision is not None
            and sandbox_decision.mode == "warn"
            and self._audit
            and engagement_id
        ):
            await self._audit.write(AuditEntry(
                engagement_id=engagement_id,
                action="sandbox.warn",
                target=target or "",
                details={
                    "tool": tool,
                    "profile": sandbox_decision.profile_name,
                    "would_have_wrapped_argv": (
                        sandbox_decision.would_have_wrapped_argv or []
                    ),
                    "notes": sandbox_decision.notes,
                },
            ))
        # The audit ``target`` field carries the identity value when present,
        # so PII filtering by target also catches OSINT entries.
        audit_target = target or ""
        if identity_target:
            audit_target = identity_target[0]
        if self._audit and engagement_id:
            await self._audit.write(AuditEntry(
                engagement_id=engagement_id,
                action="privileged_tool_execute" if requires_sudo else "tool_execute",
                target=audit_target,
                details={"command": audit_cmd, "phase": phase.value,
                         "sudo": requires_sudo, "sudo_reason": sudo_reason or None,
                         "pii": bool(pii),
                         "identity_kind": identity_target[1] if identity_target else None},
            ))

        # 7. Execute
        started_at = _sap_utcnow().isoformat(timespec="seconds")
        start = time.monotonic()
        stdout_data, stderr_data, returncode = await self._exec(
            cmd, timeout, cwd, sudo_password=sudo_password,
        )
        duration = round(time.monotonic() - start, 2)
        ended_at = _sap_utcnow().isoformat(timespec="seconds")

        # 7b. Sudo bookkeeping
        if requires_sudo:
            if returncode != 0 and self._looks_like_sudo_failure(stderr_data):
                locked = await self._vault.record_failure()
                if self._audit and engagement_id:
                    await self._audit.write(AuditEntry(
                        engagement_id=engagement_id,
                        action="sudo_failure", target=target or "",
                        details={"locked": locked, "tool": tool},
                    ))
            else:
                await self._vault.record_success()

        # Redact sudo material once on the full payloads. The store and the
        # in-memory ExecutionResult both inherit the redacted text so passwords
        # never reach disk or the LLM.
        stdout_full = redact_sudo(stdout_data) if requires_sudo else stdout_data
        stderr_full = redact_sudo(stderr_data) if requires_sudo else stderr_data
        stdout_bytes_full = len(stdout_full.encode("utf-8", errors="replace"))
        stderr_bytes_full = len(stderr_full.encode("utf-8", errors="replace"))

        # 7c. Persist FULL output to canonical store (before any cap).
        cid = call_id or ToolOutputStore.new_call_id()
        output_ref_model: ToolOutputRefModel | None = None
        store = self._store()
        if store is not None and self._run_id:
            try:
                ref = await store.store(
                    run_id=self._run_id,
                    tool=tool,
                    command_redacted=audit_cmd,
                    stdout=stdout_full.encode("utf-8", errors="replace"),
                    stderr=stderr_full.encode("utf-8", errors="replace"),
                    returncode=returncode,
                    duration_seconds=duration,
                    engagement_id=engagement_id,
                    target=target or "",
                    phase=phase.value,
                    started_at=started_at,
                    ended_at=ended_at,
                    call_id=cid,
                )
                output_ref_model = ToolOutputRefModel(**ref.to_dict())
            except Exception as exc:  # pragma: no cover — never block execution
                import logging
                logging.getLogger(__name__).error(
                    "tool output persistence failed for %s: %s", tool, exc,
                )

        # 7d. Cap in-memory copies (LLM/context budget). Disk has the full data.
        out_cap = _max_output()
        err_cap = _stderr_max_output()
        truncated = False
        if len(stdout_full) > out_cap:
            stdout_mem = stdout_full[:out_cap]
            truncated = True
        else:
            stdout_mem = stdout_full
        if len(stderr_full) > err_cap:
            stderr_mem = stderr_full[:err_cap]
            truncated = True
        else:
            stderr_mem = stderr_full

        result = ExecutionResult(
            tool=tool,
            command=audit_cmd,
            stdout=stdout_mem,
            stderr=stderr_mem,
            returncode=returncode,
            duration_seconds=duration,
            truncated=truncated,
            engagement_id=engagement_id,
            phase=phase,
            call_id=cid,
            run_id=self._run_id or "",
            output_ref=output_ref_model,
            stdout_bytes_full=stdout_bytes_full,
            stderr_bytes_full=stderr_bytes_full,
        )

        # 8. Audit after execution
        if self._audit and engagement_id:
            await self._audit.write(AuditEntry(
                engagement_id=engagement_id,
                action="tool_complete",
                target=audit_target,
                details={
                    "tool": tool,
                    "returncode": returncode,
                    "duration_seconds": duration,
                    "truncated": truncated,
                    "call_id": cid,
                    "run_id": self._run_id or "",
                    "stdout_bytes_full": stdout_bytes_full,
                    "stderr_bytes_full": stderr_bytes_full,
                    "output_ref_uri": (
                        output_ref_model.stdout_uri if output_ref_model else ""
                    ),
                    "pii": bool(pii),
                },
            ))

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tool(tool: str) -> None:
        allowed = _allowed_tools()
        if allowed and tool not in allowed:
            raise SecurityError(
                f"Tool '{tool}' is not on the allowlist. "
                f"Allowed: {sorted(allowed)}"
            )

    @staticmethod
    def _check_args(args: list[str]) -> None:
        joined = " ".join(args)
        for raw, pat in compile_blocked_patterns():
            if pat.search(joined):
                raise SecurityError(
                    f"Argument string contains a blocked pattern: {raw!r}"
                )

    @staticmethod
    async def _exec(
        cmd: list[str],
        timeout: int,
        cwd: str | None,
        sudo_password: bytes | None = None,
    ) -> tuple[str, str, int]:
        # start_new_session=True puts the child in its own process group so we
        # can SIGKILL the entire tree on timeout (nmap workers, ssh subshells,
        # ansible forks…). Without it, proc.kill() only signals the leader and
        # leaves descendants orphaned to the init reaper.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if sudo_password else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
        )
        stdin_payload: bytes | None = None
        if sudo_password is not None:
            stdin_payload = sudo_password + b"\n"

        cap = _persist_max_bytes()
        overflow_marker = (
            f"\n[TRUNCATED at {cap} bytes -- runaway output]\n".encode()
        )
        overflow_event = asyncio.Event()

        async def _drain(stream: asyncio.StreamReader | None) -> tuple[bytearray, bool]:
            """Read up to ``cap`` bytes from a stream; signal overflow on cap hit."""
            buf = bytearray()
            if stream is None:
                return buf, False
            overflow = False
            while True:
                # Bounded chunk read avoids blocking forever on slow streams.
                try:
                    chunk = await stream.read(65536)
                except (asyncio.CancelledError, ConnectionResetError):
                    break
                if not chunk:
                    break
                if len(buf) + len(chunk) > cap:
                    take = max(0, cap - len(buf))
                    buf.extend(chunk[:take])
                    overflow = True
                    # Trip the kill switch so the producer stops emitting; do
                    # NOT loop reading-and-discarding here because an
                    # unbounded producer (e.g. ``yes``) never sends EOF.
                    overflow_event.set()
                    break
                buf.extend(chunk)
            return buf, overflow

        async def _kill_on_overflow() -> None:
            try:
                await overflow_event.wait()
            except asyncio.CancelledError:
                return
            await _kill_process_tree(proc)

        async def _feed_stdin() -> None:
            if proc.stdin is None or stdin_payload is None:
                return
            try:
                proc.stdin.write(stdin_payload)
                await proc.stdin.drain()
                proc.stdin.close()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        try:
            stdin_task = asyncio.create_task(_feed_stdin())
            stdout_task = asyncio.create_task(_drain(proc.stdout))
            stderr_task = asyncio.create_task(_drain(proc.stderr))
            killer_task = asyncio.create_task(_kill_on_overflow())
            try:
                stdout_res, stderr_res = await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task),
                    timeout=float(timeout),
                )
                await proc.wait()
            except TimeoutError:
                await _kill_process_tree(proc)
                # Give drain tasks a moment to settle.
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        asyncio.gather(stdout_task, stderr_task, return_exceptions=True),
                        timeout=1.0,
                    )
                killer_task.cancel()
                with contextlib.suppress(BaseException):
                    await killer_task
                return (
                    f"[TIMEOUT] Process '{cmd[0]}' killed after {timeout}s",
                    "",
                    -1,
                )
            finally:
                stdin_task.cancel()
                with contextlib.suppress(BaseException):
                    await stdin_task

            raw_out, overflow_out = stdout_res
            raw_err, overflow_err = stderr_res
            if overflow_out or overflow_err:
                # Hard kill: a tool emitting >cap bytes is unbounded; we
                # already captured the prefix the operator needs to triage.
                # The killer task may have already fired; this is idempotent.
                await _kill_process_tree(proc)
                if overflow_out:
                    raw_out.extend(overflow_marker)
                if overflow_err:
                    raw_err.extend(overflow_marker)
            killer_task.cancel()
            with contextlib.suppress(BaseException):
                await killer_task
        finally:
            if stdin_payload is not None:
                ba = bytearray(stdin_payload)
                for i in range(len(ba)):
                    ba[i] = 0

        stdout = bytes(raw_out).decode("utf-8", errors="replace")
        stderr = bytes(raw_err).decode("utf-8", errors="replace")
        return stdout, stderr, proc.returncode or 0

    # ── sudo plumbing ──────────────────────────────────────────────────────

    async def _acquire_sudo(
        self,
        tool: str,
        args: list[str],
        engagement_id: str,
        sudo_reason: str,
    ) -> bytes:
        """Return a *bytes copy* of the sudo password, requesting unlock if needed."""
        if not await self._vault.is_unlocked():
            if self._gate is None:
                raise SudoLocked(
                    f"Tool '{tool}' requires sudo, vault is locked, no approval gate "
                    f"configured. Unlock the vault from the dashboard or supply an "
                    f"AutoApproveGate for non-interactive runs."
                )
            decision = await self._gate.request(
                reason="sudo_required",
                summary=f"{tool} requires sudo ({sudo_reason})",
                details={"tool": tool, "args": args, "sudo_reason": sudo_reason},
            )
            if decision.action != "allow":
                raise SudoLocked(
                    f"Sudo elevation denied for '{tool}': {decision.reason}"
                )
            if not await self._vault.is_unlocked():
                raise SudoLocked(
                    "Sudo vault still locked after approval — operator must unlock "
                    "via /api/sudo/unlock before retrying."
                )
        async with self._vault.borrow() as pw:
            return bytes(pw)  # caller owns this copy

    @staticmethod
    def _looks_like_sudo_failure(stderr: str) -> bool:
        if not stderr:
            return False
        markers = (
            "incorrect password", "sorry, try again", "3 incorrect password attempts",
            "a password is required",
        )
        low = stderr.lower()
        return any(m in low for m in markers)
