"""
sap_dashboard/backend/ws.py — Per-run event broker.

For each run_id we keep:
  * a deque of events (in-memory ring, last N)
  * a JSONL append-only log on disk (replay across reconnect)
  * a list of asyncio.Queue subscribers (active WS clients)

The broker exposes a single ``publish(run_id, event)`` entry-point that
the orchestrator calls (via a callback) for every step.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .deps import REPO_ROOT

_EVENT_RING_SIZE = 500


class RunBroker:
    def __init__(self) -> None:
        self._subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._ring: dict[str, deque[dict]] = defaultdict(
            lambda: deque(maxlen=_EVENT_RING_SIZE)
        )
        self._seq: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        self._runs_dir = REPO_ROOT / "sessions" / "runs"
        self._runs_dir.mkdir(parents=True, exist_ok=True)

    def _logfile(self, run_id: str) -> Path:
        d = self._runs_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d / "events.jsonl"

    async def publish(self, run_id: str, event: dict[str, Any]) -> None:
        async with self._lock:
            self._seq[run_id] += 1
            payload = {**event, "seq": self._seq[run_id], "ts": event.get("ts") or time.time()}
            self._ring[run_id].append(payload)
            try:
                with open(self._logfile(run_id), "a") as f:
                    f.write(json.dumps(payload, default=str) + "\n")
            except Exception:
                pass
            for q in list(self._subs[run_id]):
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    pass

    def subscribe(self, run_id: str, from_seq: int = 0) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1024)
        # Drain history first
        for ev in self._ring[run_id]:
            if ev["seq"] > from_seq:
                q.put_nowait(ev)
        self._subs[run_id].append(q)
        return q

    def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        try:
            self._subs[run_id].remove(q)
        except ValueError:
            pass

    def history(self, run_id: str, from_seq: int = 0) -> list[dict]:
        return [ev for ev in self._ring[run_id] if ev["seq"] > from_seq]


_BROKER: RunBroker | None = None


def get_broker() -> RunBroker:
    global _BROKER
    if _BROKER is None:
        _BROKER = RunBroker()
    return _BROKER
