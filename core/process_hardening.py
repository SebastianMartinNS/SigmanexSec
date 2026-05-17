"""
core/process_hardening.py — Process-level memory & coredump protections (P2.4).

These are applied early in the lifecycle of any long-running SAP component
(dashboard backend, CLI agent, sudo broker) so that secrets resident in the
process address space — session signing key, sudo password, LLM API key,
RBAC user table — cannot leak via:

  * Core dumps               → ``RLIMIT_CORE = 0`` + ``prctl(PR_SET_DUMPABLE, 0)``
  * Ptrace attach by peer    → ``prctl(PR_SET_DUMPABLE, 0)``
  * Swap                     → optional ``mlockall(MCL_CURRENT|MCL_FUTURE)``
                                 (requires CAP_IPC_LOCK, gated behind
                                 ``SAP_MLOCK_ALL=1``).

All operations are best-effort: on platforms where the syscall is missing
or the privilege is not granted, we silently skip rather than fail.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import resource
import sys
from dataclasses import dataclass


@dataclass
class HardeningStatus:
    rlimit_core_zero:    bool = False
    pr_set_dumpable_off: bool = False
    mlockall_done:       bool = False
    notes: list[str] | None = None

    def to_dict(self) -> dict:
        return {
            "rlimit_core_zero":    self.rlimit_core_zero,
            "pr_set_dumpable_off": self.pr_set_dumpable_off,
            "mlockall_done":       self.mlockall_done,
            "notes":               list(self.notes or []),
        }


_LIBC = None
try:
    _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
except OSError:
    _LIBC = None


def _note(status: HardeningStatus, msg: str) -> None:
    if status.notes is None:
        status.notes = []
    status.notes.append(msg)


def _set_rlimit_core_zero(status: HardeningStatus) -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        status.rlimit_core_zero = True
    except (ValueError, OSError) as exc:
        _note(status, f"rlimit_core: {exc}")


def _prctl_set_undumpable(status: HardeningStatus) -> None:
    if _LIBC is None or not sys.platform.startswith("linux"):
        return
    if not hasattr(_LIBC, "prctl"):
        return
    PR_SET_DUMPABLE = 4
    try:
        rc = _LIBC.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        if rc == 0:
            status.pr_set_dumpable_off = True
    except OSError as exc:
        _note(status, f"prctl: {exc}")


def _mlockall(status: HardeningStatus) -> None:
    if os.environ.get("SAP_MLOCK_ALL", "").lower() not in ("1", "true", "yes"):
        return
    if _LIBC is None or not sys.platform.startswith("linux"):
        return
    if not hasattr(_LIBC, "mlockall"):
        return
    MCL_CURRENT, MCL_FUTURE, _MCL_ONFAULT = 1, 2, 4
    try:
        rc = _LIBC.mlockall(MCL_CURRENT | MCL_FUTURE)
        if rc == 0:
            status.mlockall_done = True
            # Phase 5: verify with mincore() that at least one page of our
            # own VM is actually resident — catches kernels that silently
            # ignore mlockall under low-memory pressure (rare but real).
            _verify_mlock_with_mincore(status)
        else:
            errno = ctypes.get_errno()
            _note(status, f"mlockall errno={errno}")
    except OSError as exc:
        _note(status, f"mlockall: {exc}")


def _verify_mlock_with_mincore(status: HardeningStatus) -> None:
    """Probe a single page with mincore(2). If the page is not resident,
    mlockall did not actually pin memory — log a critical note so an
    operator running with ``SAP_MLOCK_ALL=1`` knows the protection
    silently failed."""
    if not hasattr(_LIBC, "mincore"):
        return
    try:
        page_size = os.sysconf("SC_PAGESIZE") if hasattr(os, "sysconf") else 4096
    except (ValueError, OSError):
        page_size = 4096
    try:
        # Allocate a page of bytes and force a write so it is mapped.
        buf = ctypes.create_string_buffer(b"\x01" * page_size)
        addr = ctypes.cast(buf, ctypes.c_void_p).value
        if addr is None:
            return
        # mincore requires the address to be page-aligned.
        page_addr = addr - (addr % page_size)
        vec = (ctypes.c_ubyte * 1)()
        rc = _LIBC.mincore(
            ctypes.c_void_p(page_addr),
            ctypes.c_size_t(page_size),
            vec,
        )
        if rc != 0:
            errno = ctypes.get_errno()
            _note(status, f"mincore errno={errno}")
            return
        if not (vec[0] & 1):
            # Page bit 0 indicates "in core". 0 ⇒ swapped/non-resident:
            # mlockall claimed success but did not actually pin.
            _note(status, "mlockall verification failed: page not resident")
            status.mlockall_done = False
    except (OSError, ValueError) as exc:
        _note(status, f"mincore probe: {exc}")


def harden_process() -> HardeningStatus:
    """Apply all P2.4 process-level secret-protection mitigations."""
    s = HardeningStatus()
    _set_rlimit_core_zero(s)
    _prctl_set_undumpable(s)
    _mlockall(s)
    return s
