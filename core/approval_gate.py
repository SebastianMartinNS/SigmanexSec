"""
core/approval_gate.py — Async human-in-the-loop approval primitive.

Used by:

  * Step Mode (every tool call must be approved by the operator)
  * Sudo workflow (privileged tool exec when vault is locked)
  * Out-of-scope target overrides (operator may grant a one-shot exception)

The orchestrator/executor call ``await gate.request(...)`` and block on a
single ``asyncio.Future``. The dashboard backend resolves the gate via
``gate.resolve(gate_id, decision)``.

In CLI / non-interactive mode an ``AutoApproveGate`` or ``AutoDenyGate`` can
be used.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# ─────────────────────────────────────────────
# Data shapes
# ─────────────────────────────────────────────

@dataclass
class ApprovalRequest:
    gate_id: str
    reason: str               # sudo_required | step_mode | out_of_scope | destructive_flag
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class ApprovalDecision:
    gate_id: str
    action: str               # "allow" | "deny"
    reason: str = ""
    decided_by: str = ""
    decided_at: float = field(default_factory=time.time)


# ─────────────────────────────────────────────
# Base gate
# ─────────────────────────────────────────────

class ApprovalGate:
    """
    Async approval gate. Default behaviour: deny on timeout.

    Subscribers can attach an ``on_pending`` callback that fires whenever a
    new request is created — used by the orchestrator to push a WebSocket
    event to the dashboard.
    """

    def __init__(
        self,
        timeout_seconds: int = 300,
        on_pending: Callable[[ApprovalRequest], None] | None = None,
    ):
        self._timeout = timeout_seconds
        self._on_pending = on_pending
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = asyncio.Lock()

    # ── orchestrator side ──────────────────────────────────────────────────

    async def request(
        self,
        reason: str,
        summary: str,
        details: dict[str, Any] | None = None,
        gate_id: str | None = None,
        timeout_seconds: int | None = None,
    ) -> ApprovalDecision:
        gid = gate_id or f"g_{uuid.uuid4().hex[:12]}"
        req = ApprovalRequest(
            gate_id=gid, reason=reason, summary=summary,
            details=details or {},
        )
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[ApprovalDecision] = loop.create_future()
        async with self._lock:
            self._pending[gid] = fut
            self._requests[gid] = req

        if self._on_pending:
            try:
                self._on_pending(req)
            except Exception:
                pass

        timeout = timeout_seconds if timeout_seconds is not None else self._timeout
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except TimeoutError:
            await self._cleanup(gid)
            return ApprovalDecision(
                gate_id=gid, action="deny",
                reason=f"timeout after {timeout}s", decided_by="auto",
            )

    # ── dashboard side ─────────────────────────────────────────────────────

    async def resolve(
        self,
        gate_id: str,
        action: str,
        reason: str = "",
        decided_by: str = "operator",
    ) -> bool:
        if action not in ("allow", "deny"):
            raise ValueError(f"Invalid action: {action}")
        async with self._lock:
            fut = self._pending.pop(gate_id, None)
            self._requests.pop(gate_id, None)
        if fut is None or fut.done():
            return False
        fut.set_result(ApprovalDecision(
            gate_id=gate_id, action=action, reason=reason, decided_by=decided_by,
        ))
        return True

    async def list_pending(self) -> list[ApprovalRequest]:
        async with self._lock:
            return list(self._requests.values())

    async def _cleanup(self, gate_id: str) -> None:
        async with self._lock:
            self._pending.pop(gate_id, None)
            self._requests.pop(gate_id, None)


# ─────────────────────────────────────────────
# Non-interactive variants
# ─────────────────────────────────────────────

class AutoApproveGate(ApprovalGate):
    """Used in CLI execution mode when no human is available."""
    async def request(self, reason, summary, details=None, gate_id=None,
                      timeout_seconds=None):  # type: ignore[override]
        return ApprovalDecision(
            gate_id=gate_id or f"g_{uuid.uuid4().hex[:8]}",
            action="allow", reason="auto-approved (non-interactive)",
            decided_by="auto",
        )


class AutoDenyGate(ApprovalGate):
    """Used as a hard wall in tests."""
    async def request(self, reason, summary, details=None, gate_id=None,
                      timeout_seconds=None):  # type: ignore[override]
        return ApprovalDecision(
            gate_id=gate_id or f"g_{uuid.uuid4().hex[:8]}",
            action="deny", reason="auto-denied", decided_by="auto",
        )
