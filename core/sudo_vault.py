"""
core/sudo_vault.py — In-memory sudo password vault with TTL.

Design constraints (see PENTEST_AGENT_MCP_SPEC.md §18):

  * Password held as ``bytearray`` (NOT ``str``) so we can zero it on lock.
  * On Linux we ``mlock(2)`` the buffer to keep it out of swap.
  * Never serialised: not in DB, not in audit log, not echoed back to API.
  * Never passed via argv: sudo is always invoked with ``-S`` and the password
    is written exactly once on the child's stdin.
  * Hard-cap TTL (default 900 s); inactivity timer resets on each borrow.
  * After ``max_failures`` consecutive sudo errors → automatic lock + flag.

This module is intentionally framework-agnostic so it can be reused by both
the dashboard backend and the orchestrator without circular imports.
"""
from __future__ import annotations

import asyncio
import contextlib
import ctypes
import ctypes.util
import os
import time
from typing import AsyncIterator, Optional


# ─────────────────────────────────────────────
# mlock helpers (Linux/macOS); silent no-op elsewhere.
# ─────────────────────────────────────────────

_libc = None
try:
    _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
except (OSError, TypeError):  # pragma: no cover
    _libc = None


def _buf_addr(buf: bytearray) -> ctypes.c_void_p:
    arr = (ctypes.c_char * len(buf)).from_buffer(buf)
    return ctypes.c_void_p(ctypes.addressof(arr))


def _mlock(buf: bytearray) -> bool:
    """Best-effort mlock; returns True on success."""
    if _libc is None or not hasattr(_libc, "mlock") or len(buf) == 0:
        return False
    try:
        return _libc.mlock(_buf_addr(buf), ctypes.c_size_t(len(buf))) == 0
    except Exception:  # pragma: no cover
        return False


def _munlock(buf: bytearray) -> None:
    if _libc is None or not hasattr(_libc, "munlock") or len(buf) == 0:
        return
    try:
        _libc.munlock(_buf_addr(buf), ctypes.c_size_t(len(buf)))
    except Exception:  # pragma: no cover
        pass


def _zeroize(buf: bytearray) -> None:
    """Overwrite buffer in place with NULs."""
    for i in range(len(buf)):
        buf[i] = 0


# ─────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────

class SudoLocked(Exception):
    """Raised when a privileged operation is requested but the vault is locked."""


class SudoFailed(Exception):
    """Raised when sudo rejects the cached password."""


# ─────────────────────────────────────────────
# Vault
# ─────────────────────────────────────────────

class SudoVault:
    """
    Singleton-like in-memory store for the operator's sudo password.

    Lifecycle:
        unlock(pw, ttl) → buffer mlocked, expires_at set
        borrow()        → async ctx mgr yielding bytes copy on demand
        lock()          → zeroize + munlock + reset state
    """

    def __init__(
        self,
        default_ttl_seconds: int = 600,
        max_ttl_seconds: int = 900,
        max_failures_before_lock: int = 3,
        inactivity_lock_seconds: int = 300,
    ):
        self._buf: Optional[bytearray] = None
        self._expires_at: float = 0.0
        self._last_use: float = 0.0
        self._failures: int = 0
        self._unlock_count: int = 0
        self._lock = asyncio.Lock()

        self._default_ttl = default_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._max_failures = max_failures_before_lock
        self._inactivity = inactivity_lock_seconds

    # ── Public API ─────────────────────────────────────────────────────────

    async def unlock(self, password: str, ttl_seconds: Optional[int] = None) -> None:
        if not password:
            raise ValueError("Empty password")
        ttl = min(ttl_seconds or self._default_ttl, self._max_ttl)
        async with self._lock:
            self._zeroize_locked()
            data = password.encode("utf-8")
            buf = bytearray(data)
            _mlock(buf)
            self._buf = buf
            now = time.monotonic()
            self._expires_at = now + ttl
            self._last_use = now
            self._failures = 0
            self._unlock_count += 1
            # Best-effort: prevent core dumps from leaking the password.
            # Only applied when this vault is the *primary* in-process holder
            # of secret material (broker process). When the vault sits behind
            # the broker proxy, the dashboard process never holds the secret
            # and disabling its core dumps is an unwanted side-effect.
            if os.environ.get("SAP_SUDO_BROKER_PROCESS") == "1":
                self._set_undumpable()

    async def lock(self) -> None:
        async with self._lock:
            self._zeroize_locked()

    async def is_unlocked(self) -> bool:
        async with self._lock:
            return self._is_unlocked_locked()

    async def status(self) -> dict:
        async with self._lock:
            unlocked = self._is_unlocked_locked()
            return {
                "locked": not unlocked,
                "expires_at_monotonic": self._expires_at if unlocked else 0.0,
                "ttl_remaining_seconds": max(0.0, self._expires_at - time.monotonic())
                if unlocked else 0.0,
                "last_use_monotonic": self._last_use,
                "failures": self._failures,
                "unlock_count": self._unlock_count,
            }

    @contextlib.asynccontextmanager
    async def borrow(self) -> AsyncIterator[bytes]:
        """
        Async context manager yielding a *copy* of the password as bytes.
        The copy is zeroized on context exit. The vault remains unlocked
        unless the borrow records a failure via ``record_failure``.
        """
        async with self._lock:
            if not self._is_unlocked_locked():
                raise SudoLocked("Sudo vault is locked")
            self._last_use = time.monotonic()
            assert self._buf is not None
            copy = bytearray(self._buf)
        try:
            yield bytes(copy)
        finally:
            _zeroize(copy)

    async def record_failure(self) -> bool:
        """
        Increment failure counter. If the threshold is reached the vault
        auto-locks. Returns True if locked as a result of this call.
        """
        async with self._lock:
            self._failures += 1
            if self._failures >= self._max_failures:
                self._zeroize_locked()
                return True
            return False

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._last_use = time.monotonic()

    # ── Private ────────────────────────────────────────────────────────────

    def _is_unlocked_locked(self) -> bool:
        if self._buf is None:
            return False
        now = time.monotonic()
        if now >= self._expires_at:
            self._zeroize_locked()
            return False
        if self._inactivity and (now - self._last_use) >= self._inactivity:
            self._zeroize_locked()
            return False
        return True

    def _zeroize_locked(self) -> None:
        if self._buf is not None:
            _zeroize(self._buf)
            _munlock(self._buf)
            self._buf = None
        self._expires_at = 0.0
        self._last_use = 0.0
        self._failures = 0

    @staticmethod
    def _set_undumpable() -> None:
        # Linux: prctl(PR_SET_DUMPABLE, 0) — best effort, ignored on other OS.
        try:
            if _libc is None or not hasattr(_libc, "prctl"):
                return
            PR_SET_DUMPABLE = 4
            _libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        except Exception:  # pragma: no cover
            pass


# ─────────────────────────────────────────────
# Module-level singleton (the dashboard and the executor share it).
# ─────────────────────────────────────────────

_VAULT: Optional["SudoVault"] = None
_PROXY = None


def get_sudo_vault():
    """
    Return either a local :class:`SudoVault` or a :class:`BrokerVaultProxy`
    when the broker is configured via ``SAP_SUDO_BROKER`` env var. The proxy
    is API-compatible with :class:`SudoVault` for the methods used by the
    executor and the dashboard.
    """
    global _VAULT, _PROXY
    broker_path = os.environ.get("SAP_SUDO_BROKER")
    if broker_path and os.environ.get("SAP_SUDO_BROKER_PROCESS") != "1":
        if _PROXY is None or getattr(_PROXY, "socket_path", None) != broker_path:
            from core.sudo_broker import BrokerVaultProxy
            _PROXY = BrokerVaultProxy(broker_path)
        return _PROXY
    if _VAULT is None:
        # Config is read lazily from yaml so the vault can start without it.
        try:
            import yaml
            cfg_path = os.environ.get(
                "SAP_CONFIG", os.path.join(os.path.dirname(__file__), "..", "config.yaml")
            )
            with open(cfg_path) as f:
                cfg = (yaml.safe_load(f) or {}).get("sudo", {}) or {}
            _VAULT = SudoVault(
                default_ttl_seconds=int(cfg.get("default_ttl_seconds", 600)),
                max_ttl_seconds=int(cfg.get("max_ttl_seconds", 900)),
                max_failures_before_lock=int(cfg.get("max_failures_before_lock", 3)),
                inactivity_lock_seconds=int(cfg.get("inactivity_lock_seconds", 300)),
            )
        except Exception:
            _VAULT = SudoVault()
    return _VAULT
