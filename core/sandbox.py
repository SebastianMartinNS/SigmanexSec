"""
core/sandbox.py — OS-level sandbox wrapper for tool execution.

Inserts a layer between ``core/executor.ToolExecutor.run()`` and the
underlying ``asyncio.create_subprocess_exec`` call. The tool command is
wrapped in a ``bwrap`` invocation according to a per-category profile so
out-of-scope file writes, capability escalation or unauthorised network
egress are prevented at the kernel level.

The sandbox is the second line of defence behind
``core/scope_validator`` (which validates *what* the tool is allowed to
target). It governs *how* the tool can behave once it is launched.

Mode selection (env: ``SAP_SANDBOX``)
-------------------------------------

* ``on``    — enforce. The wrapped command is what runs. Escapes are
              prevented by the kernel; profile lookup or bwrap absence
              raises ``SandboxUnavailable``.
* ``warn``  — observe. The wrapped command is computed and surfaced
              via the returned :class:`SandboxDecision` (the caller is
              expected to write a ``sandbox.warn`` audit event), but
              the **unwrapped** command runs. This is the default in
              v2.3 so operators can validate profiles against real
              engagements before flipping enforcement on in v2.4.
* ``off``   — bypass. No-op for development / CI runners where
              unprivileged user namespaces are not available.

Profiles live in ``deploy/sandbox/profiles/*.json`` and conform to
``profile.schema.json``.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from core.logging import get_logger

_log = get_logger("sandbox")

Mode = Literal["on", "warn", "off"]


# ── Public API ────────────────────────────────────────────────────────────


class SandboxUnavailable(RuntimeError):
    """Raised in ``on`` mode when the sandbox cannot be applied (no bwrap,
    profile missing, etc.). Never raised in ``warn`` or ``off`` — those
    modes are fail-open by design."""


@dataclass(frozen=True)
class SandboxDecision:
    """Outcome of computing the sandbox wrapping for a single command."""

    mode: Mode
    profile_name: str
    wrapped_argv: list[str]
    wrapped_env: dict[str, str]
    notes: list[str] = field(default_factory=list)
    # ``would_have_wrapped_argv`` is set in ``warn`` mode so the caller
    # can audit the wrapped command that *would* run under enforcement.
    would_have_wrapped_argv: list[str] | None = None

    @property
    def enforced(self) -> bool:
        return self.mode == "on"


def current_mode() -> Mode:
    raw = (os.environ.get("SAP_SANDBOX") or "warn").strip().lower()
    if raw in ("on", "1", "true", "enforce", "yes"):
        return "on"
    if raw in ("off", "0", "false", "disable", "no"):
        return "off"
    return "warn"


def is_available() -> bool:
    """True if a backend (bwrap or firejail) is installed."""
    return bool(shutil.which("bwrap") or shutil.which("firejail"))


def reset_caches() -> None:
    """Drop cached profile dir / profile contents. Used by tests."""
    _profile_dir.cache_clear()
    load_profile.cache_clear()


@functools.lru_cache(maxsize=1)
def _profile_dir() -> Path:
    explicit = os.environ.get("SAP_SANDBOX_PROFILE_DIR")
    if explicit:
        return Path(explicit)
    repo_default = Path(__file__).resolve().parent.parent / "deploy" / "sandbox" / "profiles"
    system_default = Path("/etc/sap-pentest/sandbox/profiles")
    for p in (repo_default, system_default):
        if p.is_dir():
            return p
    return repo_default


@functools.lru_cache(maxsize=32)
def load_profile(name: str) -> dict[str, Any]:
    """Return the parsed profile JSON for *name*. Raises FileNotFoundError."""
    path = _profile_dir() / f"{name}.json"
    if not path.is_file():
        raise FileNotFoundError(f"sandbox profile {name!r} not found at {path}")
    with path.open("r", encoding="utf-8") as fp:
        data: dict[str, Any] = json.load(fp)
    return data


def wrap(
    profile_name: str,
    argv: list[str],
    env: dict[str, str] | None = None,
    *,
    run_id: str = "",
) -> SandboxDecision:
    """Compute the sandbox decision for *argv*.

    * ``off``  → returns argv unchanged with a single note.
    * ``warn`` → returns argv unchanged; ``would_have_wrapped_argv``
                 carries the wrapped form for auditing.
    * ``on``   → returns the wrapped argv; raises
                 :class:`SandboxUnavailable` if either bwrap is missing
                 or the profile cannot be loaded.

    The function never mutates the caller's environment or argv.
    """

    mode = current_mode()
    notes: list[str] = []
    env_copy = dict(env or os.environ)
    argv_copy = list(argv)

    if mode == "off":
        notes.append("sandbox disabled via SAP_SANDBOX=off")
        return SandboxDecision(
            mode="off",
            profile_name=profile_name,
            wrapped_argv=argv_copy,
            wrapped_env=env_copy,
            notes=notes,
        )

    try:
        profile = load_profile(profile_name)
    except FileNotFoundError as exc:
        notes.append(f"profile not found: {exc}")
        if mode == "warn":
            return SandboxDecision(
                mode="warn",
                profile_name=profile_name,
                wrapped_argv=argv_copy,
                wrapped_env=env_copy,
                notes=notes,
            )
        raise SandboxUnavailable(str(exc)) from exc

    if not shutil.which("bwrap"):
        notes.append("bwrap not on PATH; sandbox could not be enforced")
        if mode == "warn":
            return SandboxDecision(
                mode="warn",
                profile_name=profile_name,
                wrapped_argv=argv_copy,
                wrapped_env=env_copy,
                notes=notes,
                would_have_wrapped_argv=_build_bwrap_argv(profile, argv_copy, run_id=run_id),
            )
        raise SandboxUnavailable(
            "bwrap missing from PATH; install bubblewrap or set SAP_SANDBOX=off"
        )

    wrapped = _build_bwrap_argv(profile, argv_copy, run_id=run_id)
    notes.append(f"bwrap profile '{profile_name}' applied")

    if mode == "warn":
        return SandboxDecision(
            mode="warn",
            profile_name=profile_name,
            wrapped_argv=argv_copy,
            wrapped_env=env_copy,
            notes=notes,
            would_have_wrapped_argv=wrapped,
        )

    # mode == "on"
    return SandboxDecision(
        mode="on",
        profile_name=profile_name,
        wrapped_argv=wrapped,
        wrapped_env=env_copy,
        notes=notes,
    )


# ── Internal: bwrap argv composition ─────────────────────────────────────


def _build_bwrap_argv(
    profile: dict[str, Any],
    tool_argv: list[str],
    *,
    run_id: str,
) -> list[str]:
    """Compose the bwrap command line wrapping *tool_argv* under *profile*."""

    args: list[str] = ["bwrap"]

    # Read-only binds. bwrap requires both source and target paths; we
    # mirror the host path inside the sandbox so absolute references in
    # the tool (config files, libraries) keep resolving.
    for path in profile.get("bind_ro", []) or []:
        if Path(path).exists():
            args += ["--ro-bind", path, path]

    # Per-run RW workdir.
    workdir_template = profile.get("workdir_template")
    if workdir_template:
        workdir = workdir_template.format(run_id=run_id or "default")
        Path(workdir).mkdir(parents=True, exist_ok=True)
        args += ["--bind", workdir, profile.get("workdir_mount", "/work")]

    # Extra explicit RW binds.
    for pair in profile.get("bind_rw", []) or []:
        if len(pair) == 2:
            src, dst = pair
            args += ["--bind", src, dst]

    # Minimal /dev /proc and tmpfs mounts.
    if profile.get("dev", True):
        args += ["--dev", "/dev"]
    if profile.get("proc", True):
        args += ["--proc", "/proc"]
    for path in profile.get("tmpfs", ["/tmp"]) or []:
        args += ["--tmpfs", path]

    # Session and lifecycle: tie sandbox lifetime to caller and isolate
    # the controlling terminal so the tool cannot reach back via TIOCSTI.
    args += ["--new-session", "--die-with-parent"]
    if profile.get("as_pid_1", True):
        args += ["--as-pid-1"]

    # Namespace policy.
    if profile.get("unshare_user", True):
        args += ["--unshare-user"]
    if profile.get("unshare_pid", True):
        args += ["--unshare-pid"]
    if profile.get("unshare_ipc", True):
        args += ["--unshare-ipc"]
    if profile.get("unshare_uts", True):
        args += ["--unshare-uts"]
    if (profile.get("network_policy") or "in_scope") == "none":
        args += ["--unshare-net"]
    # For "in_scope" / "domain_allowlist" the network namespace is left
    # attached to the host; egress filtering is the scope_validator's
    # responsibility today. A future revision may attach nftables here.

    # Capability policy.
    for cap in (profile.get("caps_drop", ["ALL"]) or []):
        args += ["--cap-drop", cap]
    for cap in (profile.get("caps_keep", []) or []):
        args += ["--cap-add", cap]

    # End of bwrap args; tool follows.
    args.append("--")
    args.extend(tool_argv)
    return args


# ── Profile name resolution helper ───────────────────────────────────────


# Default mapping from MCP server suffix → sandbox profile. Used by
# ToolExecutor when the caller does not pass an explicit ``sandbox_profile``.
DEFAULT_PROFILE_BY_CATEGORY: dict[str, str] = {
    "recon": "recon",
    "exploit": "exploit",
    "osint": "osint",
    "blueteam": "blueteam",
    "parrot": "parrot",
    "engagement": "engagement",
}


def resolve_profile(
    explicit: str | None,
    *,
    category_hint: str | None = None,
) -> str:
    """Return the profile name to use, defaulting to ``parrot`` if nothing
    else fits. Never raises — the conservative fallback profile is the
    answer when the caller does not know."""
    if explicit:
        return explicit
    if category_hint and category_hint in DEFAULT_PROFILE_BY_CATEGORY:
        return DEFAULT_PROFILE_BY_CATEGORY[category_hint]
    return "parrot"
