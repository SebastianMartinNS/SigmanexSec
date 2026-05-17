"""
sap_dashboard/backend/run_manager.py — Tracks active agent runs.

Each run is an asyncio.Task running an Orchestrator with a callback that
publishes events through the RunBroker. Approval gates from STEP mode are
also exposed here so the dashboard can resolve them.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from agent.orchestrator import Orchestrator
from agent.run_modes import RunMode
from core.approval_gate import ApprovalGate, AutoApproveGate
from core.time_utils import utcnow as _sap_utcnow

from .ws import get_broker


@dataclass
class RunHandle:
    run_id: str
    engagement_id: str
    objective: str
    mode: str
    state: str = "running"  # running | paused | done | error | killed
    started_at: datetime = field(default_factory=_sap_utcnow)
    finished_at: datetime | None = None
    iterations: int = 0
    error: str | None = None
    final_text: str | None = None
    task: asyncio.Task | None = None
    gate: ApprovalGate | None = None
    pause_event: asyncio.Event | None = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "engagement_id": self.engagement_id,
            "objective": self.objective,
            "mode": self.mode,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "iterations": self.iterations,
            "error": self.error,
            "final_text": self.final_text,
        }


class RunManager:
    def __init__(self) -> None:
        self._runs: dict[str, RunHandle] = {}
        self._broker = get_broker()

    def list(self) -> list[RunHandle]:
        return list(self._runs.values())

    def get(self, run_id: str) -> RunHandle | None:
        return self._runs.get(run_id)

    async def start(
        self,
        engagement_id: str,
        objective: str,
        mode: str = "execution",
        max_iterations: int = 12,
    ) -> RunHandle:
        run_id = f"r_{uuid.uuid4().hex[:12]}"
        try:
            run_mode = RunMode(mode)
        except ValueError:
            run_mode = RunMode.EXECUTION

        # Step mode -> real ApprovalGate that publishes "approval_required"
        # events; Execution/Planning -> auto-approve.
        if run_mode == RunMode.STEP:
            async def _on_pending(req):
                await self._broker.publish(run_id, {
                    "type": "approval_required",
                    "gate_id": req.gate_id,
                    "reason": req.reason,
                    "summary": req.summary,
                    "details": req.details,
                })
            gate: ApprovalGate = ApprovalGate(on_pending=_on_pending)
        else:
            gate = AutoApproveGate()

        handle = RunHandle(
            run_id=run_id,
            engagement_id=engagement_id,
            objective=objective,
            mode=run_mode.value,
            gate=gate,
            pause_event=asyncio.Event(),
        )
        handle.pause_event.set()  # not paused

        loop = asyncio.get_running_loop()

        def _on_message(role: str, text: str) -> None:
            # Track iteration progress so the dashboard shows live counters
            # instead of "iter=0" forever (the orchestrator emits this at
            # the top of every agentic loop iteration).
            if role == "iteration":
                try:
                    handle.iterations = int(text)
                except (TypeError, ValueError):
                    pass
            event = {"type": role, "text": text}
            asyncio.run_coroutine_threadsafe(
                self._broker.publish(run_id, event), loop
            )

        orch = Orchestrator(
            on_message=_on_message,
            mode=run_mode,
            approval_gate=gate,
            run_id=run_id,
        )

        async def _runner():
            try:
                await self._broker.publish(run_id, {
                    "type": "run_started",
                    "run_id": run_id,
                    "engagement_id": engagement_id,
                    "objective": objective,
                    "mode": run_mode.value,
                })
                # Spawn MCP server subprocesses + harvest tool registry.
                # Without this the LLM sees an empty tool list and hallucinates.
                await orch.initialize()
                await self._broker.publish(run_id, {
                    "type": "tools_loaded",
                    "count": len(orch._registry._tools),
                    "servers": list(orch._registry._sessions.keys()),
                })
                final_text = await orch.run(
                    engagement_id=engagement_id,
                    objective=objective,
                    max_iterations=max_iterations,
                )
                handle.final_text = final_text
                handle.state = "done"
                await self._broker.publish(run_id, {
                    "type": "done", "final_text": final_text,
                })
            except asyncio.CancelledError:
                handle.state = "killed"
                await self._broker.publish(run_id, {"type": "error", "error": "killed"})
                raise
            except Exception as e:
                handle.state = "error"
                handle.error = str(e)
                await self._broker.publish(run_id, {"type": "error", "error": str(e)})
            finally:
                handle.finished_at = _sap_utcnow()
                try:
                    await orch.close()
                except Exception:
                    pass

        handle.task = asyncio.create_task(_runner())
        self._runs[run_id] = handle
        return handle

    async def control(self, run_id: str, action: str) -> RunHandle:
        h = self._runs.get(run_id)
        if not h:
            raise KeyError(run_id)
        if action == "pause":
            if h.pause_event:
                h.pause_event.clear()
            h.state = "paused"
        elif action == "resume":
            if h.pause_event:
                h.pause_event.set()
            if h.state == "paused":
                h.state = "running"
        elif action == "kill":
            if h.task and not h.task.done():
                h.task.cancel()
            h.state = "killed"
        else:
            raise ValueError(f"unknown action: {action}")
        await self._broker.publish(run_id, {"type": "control", "action": action})
        return h

    async def approve(self, run_id: str, gate_id: str, decision: str, reason: str = "", user: str = "") -> bool:
        h = self._runs.get(run_id)
        if not h or not h.gate:
            return False
        action = "allow" if decision == "allow" else "deny"
        return h.gate.resolve(gate_id, action=action, reason=reason, decided_by=user)


_MGR: RunManager | None = None


def get_runs() -> RunManager:
    global _MGR
    if _MGR is None:
        _MGR = RunManager()
    return _MGR
