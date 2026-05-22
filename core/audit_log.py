"""
core/audit_log.py — Append-only, tamper-evident audit log.

Every tool execution, finding, and agent decision is written here
as newline-delimited JSON (JSONL).

The writer runs on a background asyncio task fed by an asyncio.Queue
so producers (the orchestrator + MCP servers) never block on disk I/O.
Bounded queue with drop-oldest semantics guarantees the event loop
stays responsive even under bursty audit volume.

P2.1 hardening — BLAKE2b hash-chain:
Each persisted line is a JSON object with the original ``AuditEntry``
fields plus two extra keys:
    ``_prev``  — hex digest of the previous entry on the chain ("" for genesis)
    ``_hash``  — BLAKE2b-256 hex digest of ``canonical(entry) || _prev``

The current head is mirrored to a sidecar ``<audit>.head`` so a fresh
process can resume the chain after a restart. Use
``verify_audit_chain()`` to re-walk the file and detect tampering.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path

from core.models import AuditEntry
from core.paths import audit_log_path

_log = logging.getLogger(__name__)

_DEFAULT_FLUSH_INTERVAL_S = float(os.environ.get("SAP_AUDIT_FLUSH_INTERVAL_S", "0.5"))


def _queue_max() -> int:
    return int(os.environ.get("SAP_AUDIT_QUEUE_MAX", "10000"))


def _rotation_max_bytes() -> int:
    """Audit log size threshold (bytes) above which the file is rotated.

    Set to 0 (or any non-positive value) to disable rotation. Default 256 MiB
    keeps a year of moderate activity while bounding the cost of full chain
    re-verification.
    """
    try:
        v = int(os.environ.get("SAP_AUDIT_MAX_BYTES", str(256 * 1024 * 1024)))
    except (TypeError, ValueError):
        return 256 * 1024 * 1024
    return v if v > 0 else 0


class AuditLog:
    """Async append-only audit log backed by a background writer task."""

    def __init__(self, log_path: str | None = None):
        self._path = Path(log_path) if log_path else audit_log_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # P2.1: queue carries the *entry* (not a pre-serialized line) so the
        # writer can compute the hash chain sequentially under a single
        # producer-consumer.
        self._queue: asyncio.Queue[AuditEntry] = asyncio.Queue(maxsize=_queue_max())
        self._writer_task: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()
        self._dropped = 0
        # Hash-chain head, persisted in a sidecar so restarts continue the
        # chain. The genesis line uses ``_prev = ""``.
        self._head_path = self._path.with_suffix(self._path.suffix + ".head")
        self._last_hash: str = self._load_head()
        # P5 — external sinks (syslog/file) for tamper-evident shipping.
        try:
            from core.audit_sink import build_sinks_from_env
            self._sinks = build_sinks_from_env()
        except Exception:
            self._sinks = []

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _ensure_writer(self) -> None:
        if self._writer_task is None or self._writer_task.done():
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            self._writer_task = loop.create_task(
                self._writer_loop(), name="audit-log-writer"
            )

    async def _writer_loop(self) -> None:
        try:
            while not self._stopped.is_set() or not self._queue.empty():
                try:
                    first = await asyncio.wait_for(
                        self._queue.get(), timeout=_DEFAULT_FLUSH_INTERVAL_S
                    )
                except TimeoutError:
                    continue
                batch: list[AuditEntry] = [first]
                while True:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                payload = self._build_chain_payload(batch)
                try:
                    await asyncio.to_thread(self._append, payload)
                    await asyncio.to_thread(self._write_head, self._last_hash)
                except Exception as exc:  # pragma: no cover
                    _log.error("audit log write failed: %s", exc)
        finally:
            remaining: list[AuditEntry] = []
            while True:
                try:
                    remaining.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if remaining:
                with contextlib.suppress(Exception):
                    payload = self._build_chain_payload(remaining)
                    await asyncio.to_thread(self._append, payload)
                    await asyncio.to_thread(self._write_head, self._last_hash)

    def _build_chain_payload(self, entries: list[AuditEntry]) -> str:
        """Serialize entries with the BLAKE2b hash chain.

        Mutates ``self._last_hash`` to reflect the new head. Caller must
        persist it via :meth:`_write_head` after a successful append.
        """
        out: list[str] = []
        for e in entries:
            base = json.loads(e.model_dump_json())
            base["_prev"] = self._last_hash
            canon = json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")
            h = hashlib.blake2b(canon, digest_size=32).hexdigest()
            base["_hash"] = h
            out.append(json.dumps(base, separators=(",", ":")) + "\n")
            self._last_hash = h
        return "".join(out)

    def _append(self, payload: str) -> None:
        # Rotate before append if we are about to exceed the size cap. The
        # hash chain continues across the rotation boundary because
        # ``self._last_hash`` is kept in memory and written into the sidecar
        # — the first line of the new file references it via ``_prev``.
        self._maybe_rotate(extra_bytes=len(payload.encode("utf-8")))
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(payload)
            # Durability: flush + fsync so a crash between this append and
            # the head sidecar update cannot leave the sidecar pointing at
            # a hash that no longer exists on disk. The head sidecar is
            # written via os.replace() (atomic) by the caller after we
            # return.
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass
        # P5 — fan-out to external sinks. Failures are swallowed inside
        # each sink so they cannot block local audit writes.
        if self._sinks and payload:
            for line in payload.splitlines():
                if not line:
                    continue
                for sink in self._sinks:
                    try:
                        sink.emit(line)
                    except Exception:  # pragma: no cover - paranoia
                        pass

    def _maybe_rotate(self, extra_bytes: int = 0) -> None:
        """Rename the current log to ``audit.jsonl.<N>`` if it would grow
        past ``SAP_AUDIT_MAX_BYTES``. Returns silently if rotation is
        disabled or the file does not yet exist. The hash chain is
        preserved across the boundary; ``verify_audit_chain`` can be
        invoked on each archived file individually using the next file's
        first ``_prev`` as the expected tail.
        """
        cap = _rotation_max_bytes()
        if cap <= 0:
            return
        try:
            if not self._path.exists():
                # Nothing to rotate yet — the first write will create the file.
                return
            current = self._path.stat().st_size
        except OSError:
            return
        if current + extra_bytes <= cap:
            return
        # Pick the next free archive index.
        idx = 1
        while True:
            archive = self._path.with_suffix(self._path.suffix + f".{idx}")
            if not archive.exists():
                break
            idx += 1
            if idx > 10_000:  # paranoia — should never happen in practice
                _log.error("audit log rotation: too many archives (%d)", idx)
                return
        try:
            os.replace(self._path, archive)
            _log.info(
                "audit log rotated: %s -> %s (%d bytes)",
                self._path, archive, current,
            )
        except OSError as exc:
            _log.warning("audit log rotation failed: %s", exc)

    def _write_head(self, head: str) -> None:
        try:
            tmp = self._head_path.with_suffix(self._head_path.suffix + ".tmp")
            tmp.write_text(head, encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self._head_path)
        except OSError as exc:  # pragma: no cover
            _log.warning("audit head sidecar write failed: %s", exc)

    def _load_head(self) -> str:
        # Prefer the on-disk log when present (authoritative); fall back to
        # the sidecar so a freshly-rotated log still continues a known chain.
        if self._path.exists():
            try:
                with open(self._path, "rb") as f:
                    f.seek(0, os.SEEK_END)
                    end = f.tell()
                    chunk = 4096
                    pos = max(0, end - chunk)
                    f.seek(pos)
                    last = f.read().splitlines()
                for line in reversed(last):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        h = obj.get("_hash")
                        if isinstance(h, str) and h:
                            return h
                    except Exception:
                        continue
            except OSError:
                pass
        if self._head_path.exists():
            try:
                return self._head_path.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        return ""

    async def close(self) -> None:
        self._stopped.set()
        if self._writer_task is not None:
            with contextlib.suppress(Exception):
                await self._writer_task

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    async def write(self, entry: AuditEntry) -> None:
        """Enqueue an entry; never blocks. Drops oldest on saturation."""
        self._ensure_writer()
        try:
            self._queue.put_nowait(entry)
        except asyncio.QueueFull:
            with contextlib.suppress(asyncio.QueueEmpty):
                victim = self._queue.get_nowait()
                self._dropped += 1
                # Surface enough metadata to forensically reconstruct what
                # was lost without leaking the full payload (some entries
                # contain redacted-but-sensitive details). The "tool" /
                # "action" fields plus timestamp are usually sufficient to
                # cross-reference with run logs.
                try:
                    _log.error(
                        "audit_dropped action=%s actor=%s ts=%s engagement=%s",
                        getattr(victim, "action", "?"),
                        getattr(victim, "actor", "?"),
                        getattr(victim, "ts", "?"),
                        getattr(victim, "engagement_id", "?"),
                    )
                except Exception:
                    pass
            with contextlib.suppress(asyncio.QueueFull):
                self._queue.put_nowait(entry)
            if self._dropped % 100 == 1:
                _log.warning(
                    "audit queue saturated; %d entries dropped so far",
                    self._dropped,
                )

    @property
    def dropped(self) -> int:
        return self._dropped

    async def flush(self) -> None:
        self._ensure_writer()
        while not self._queue.empty():
            await asyncio.sleep(0.01)

    # ------------------------------------------------------------------
    # Reader
    # ------------------------------------------------------------------

    async def read_all(self, engagement_id: str = "") -> list[AuditEntry]:
        if not self._path.exists():
            return []

        def _read() -> list[AuditEntry]:
            entries: list[AuditEntry] = []
            with open(self._path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        # P2.1: chain fields are sidecar metadata; strip
                        # them before validating against the AuditEntry model.
                        obj.pop("_prev", None)
                        obj.pop("_hash", None)
                        if engagement_id and obj.get("engagement_id") != engagement_id:
                            continue
                        entries.append(AuditEntry(**obj))
                    except Exception:
                        continue
            return entries

        return await asyncio.to_thread(_read)


def verify_audit_chain(path: str | os.PathLike[str]) -> tuple[bool, int, str]:
    """Re-walk an audit log and verify the BLAKE2b hash chain.

    Returns ``(ok, line_number, message)``:
    * ``ok=True``  → the chain is intact; ``line_number`` = entries verified.
    * ``ok=False`` → ``line_number`` is the 1-based offending line and
      ``message`` describes the mismatch (broken hash / broken link / parse
      failure).

    The function is purely read-only and safe to call from a CLI / cron.
    """
    p = Path(path)
    if not p.exists():
        return True, 0, "log file does not exist"
    prev = ""
    n = 0
    with open(p, encoding="utf-8") as f:
        for n, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as exc:
                return False, n, f"parse error: {exc}"
            stored_prev = obj.pop("_prev", None)
            stored_hash = obj.pop("_hash", None)
            if stored_prev is None or stored_hash is None:
                return False, n, "missing chain fields"
            if stored_prev != prev:
                return False, n, "chain link mismatch"
            obj["_prev"] = prev
            canon = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
            recomputed = hashlib.blake2b(canon, digest_size=32).hexdigest()
            if recomputed != stored_hash:
                return False, n, "hash mismatch"
            prev = stored_hash
    return True, n, "ok"
