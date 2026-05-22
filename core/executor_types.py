"""
core/executor_types.py — Strongly-typed request for ``ToolExecutor.run`` (v3.0).

``ToolExecutor.run`` historically took 13 keyword parameters. That fat
interface violates ISP (callers depend on parameters they do not use)
and makes it hard to pass an executor call across processes or to log
the *intent* of a call before it executes (which Milestone A needs).

This module introduces a frozen dataclass ``ToolCallRequest`` that
captures the full intent of one executor invocation and a small
``ToolCallRequestBuilder`` for ergonomic construction. The executor
keeps its legacy ``run(tool, args, ...)`` signature for backward compat
and grows a new ``run_request(req)`` companion that takes the dataclass.

The dataclass is intentionally a plain ``@dataclass(frozen=True)`` (not
Pydantic) so it stays free of validation overhead in the hot path. Field
semantics are documented inline.

Role-aware execution
--------------------

The ``role_id`` field is what Milestone C plugs into: when not None,
``ToolExecutor.run_request`` consults ``core.role_validator.RoleValidator``
before invoking ``scope_validator``. The field is None today (single-agent
mode) and becomes meaningful when the multi-agent coordinator dispatches
a tool call on behalf of, e.g., ``recon_analyst``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from core.models import Phase


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    """One executor invocation, fully described.

    Equivalent to the kwargs of ``ToolExecutor.run`` plus the v3 ``role_id``.
    Frozen so it can be hashed/cached and so callers cannot mutate a request
    after it has been audit-logged.
    """

    # Identity ─────────────────────────────────────────────────────────────
    tool: str
    args: list[str] = field(default_factory=list)
    call_id: str = ""                       # auto-filled when empty

    # Scope / engagement ────────────────────────────────────────────────────
    engagement_id: str = ""
    phase: Phase = Phase.SCANNING
    target: str | None = None
    identity_target: tuple[str, str] | None = None   # (value, kind) for OSINT

    # Execution policy ──────────────────────────────────────────────────────
    timeout: int | None = None
    cwd: str | None = None
    requires_sudo: bool | None = None       # None = let _needs_sudo decide
    sudo_reason: str = ""
    pii: bool = False

    # Sandbox ───────────────────────────────────────────────────────────────
    sandbox_profile: str | None = None
    sandbox_category: str | None = None

    # Multi-agent (Milestone C) ─────────────────────────────────────────────
    role_id: str | None = None              # consulted by RoleValidator when set

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def with_call_id(self) -> "ToolCallRequest":
        """Return a copy with ``call_id`` populated. Idempotent."""
        if self.call_id:
            return self
        return replace(self, call_id=f"call_{uuid.uuid4().hex[:12]}")

    def to_run_kwargs(self) -> dict[str, Any]:
        """Render as kwargs accepted by ``ToolExecutor.run``.

        Kept in this module (not in ``ToolExecutor``) so the executor
        chokepoint stays free of v3-specific imports.
        """
        return {
            "engagement_id": self.engagement_id,
            "phase": self.phase,
            "timeout": self.timeout,
            "cwd": self.cwd,
            "target": self.target,
            "identity_target": self.identity_target,
            "requires_sudo": self.requires_sudo,
            "sudo_reason": self.sudo_reason,
            "call_id": self.call_id or None,
            "pii": self.pii,
            "sandbox_profile": self.sandbox_profile,
            "sandbox_category": self.sandbox_category,
        }

    @classmethod
    def builder(cls, tool: str) -> "ToolCallRequestBuilder":
        return ToolCallRequestBuilder(tool)


class ToolCallRequestBuilder:
    """Fluent builder for :class:`ToolCallRequest`.

    Use when constructing a request from a long chain of conditional
    options is more readable than a positional/keyword call::

        req = (ToolCallRequest.builder("nmap_scan")
               .args(["-sV", "-p", "80,443", "10.0.0.1"])
               .target("10.0.0.1")
               .engagement("eng_42")
               .phase(Phase.SCANNING)
               .role("recon_analyst")
               .build())
    """

    __slots__ = ("_data",)

    def __init__(self, tool: str) -> None:
        self._data: dict[str, Any] = {"tool": tool}

    def args(self, args: list[str]) -> "ToolCallRequestBuilder":
        self._data["args"] = list(args)
        return self

    def engagement(self, engagement_id: str) -> "ToolCallRequestBuilder":
        self._data["engagement_id"] = engagement_id
        return self

    def phase(self, phase: Phase) -> "ToolCallRequestBuilder":
        self._data["phase"] = phase
        return self

    def target(self, target: str) -> "ToolCallRequestBuilder":
        self._data["target"] = target
        return self

    def identity(self, value: str, kind: str) -> "ToolCallRequestBuilder":
        self._data["identity_target"] = (value, kind)
        self._data["pii"] = True
        return self

    def timeout(self, seconds: int) -> "ToolCallRequestBuilder":
        self._data["timeout"] = seconds
        return self

    def cwd(self, path: str) -> "ToolCallRequestBuilder":
        self._data["cwd"] = path
        return self

    def sudo(self, required: bool = True, reason: str = "") -> "ToolCallRequestBuilder":
        self._data["requires_sudo"] = required
        if reason:
            self._data["sudo_reason"] = reason
        return self

    def sandbox(self, profile: str, category: str | None = None) -> "ToolCallRequestBuilder":
        self._data["sandbox_profile"] = profile
        if category:
            self._data["sandbox_category"] = category
        return self

    def role(self, role_id: str) -> "ToolCallRequestBuilder":
        self._data["role_id"] = role_id
        return self

    def call_id(self, call_id: str) -> "ToolCallRequestBuilder":
        self._data["call_id"] = call_id
        return self

    def pii(self, flag: bool = True) -> "ToolCallRequestBuilder":
        self._data["pii"] = flag
        return self

    def build(self) -> ToolCallRequest:
        return ToolCallRequest(**self._data).with_call_id()
