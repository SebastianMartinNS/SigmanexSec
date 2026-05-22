"""
core/tool_output_store.py — Canonical persistence for full tool outputs.

Solves the problem of truncated/lost tool results by writing every
ExecutionResult's stdout/stderr to the filesystem (uncapped) plus an
indexed row in SQLite.

Layout::

    sessions/runs/{run_id}/tool_outputs/{call_id}/
        ├── stdout.bin[.gz]   # full stdout (gzip if > 1 MB)
        ├── stderr.bin[.gz]   # full stderr
        ├── meta.json         # tool, command, args, returncode, etc.
        └── artifacts/        # nmap -oA, sqlmap --output-dir, …

SQLite table ``tool_outputs`` (in ``sessions/assessments.db``) holds
metadata and pointers to the on-disk blobs. Listing/queries use SQL;
content reads use the filesystem.

Compression policy: gzip when raw size > 1 MiB. Below that, files stay
plaintext for easy inspection (`cat`, `less`, `grep`).
"""
from __future__ import annotations

import asyncio
import builtins
import gzip
import json
import logging
import os
import shutil
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from core.paths import assessments_db_path, sessions_dir
from core.time_utils import utcnow as _sap_utcnow

_log = logging.getLogger(__name__)

# Gzip threshold: 1 MiB raw bytes
_GZIP_THRESHOLD_BYTES = 1024 * 1024

# Default retention (days) — overridable via config or env
_DEFAULT_RETENTION_DAYS = 90


SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_outputs (
    call_id              TEXT PRIMARY KEY,
    run_id               TEXT NOT NULL,
    engagement_id        TEXT NOT NULL DEFAULT '',
    tool                 TEXT NOT NULL,
    command_redacted     TEXT NOT NULL DEFAULT '',
    target               TEXT DEFAULT '',
    phase                TEXT DEFAULT '',
    returncode           INTEGER,
    duration_seconds     REAL,
    stdout_bytes         INTEGER NOT NULL DEFAULT 0,
    stderr_bytes         INTEGER NOT NULL DEFAULT 0,
    stdout_path          TEXT,
    stderr_path          TEXT,
    artifacts_dir        TEXT,
    stdout_compressed    INTEGER NOT NULL DEFAULT 0,
    stderr_compressed    INTEGER NOT NULL DEFAULT 0,
    truncated_in_memory  INTEGER NOT NULL DEFAULT 0,
    started_at           TEXT,
    ended_at             TEXT,
    created_at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_run     ON tool_outputs(run_id);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_eng     ON tool_outputs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_created ON tool_outputs(created_at);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_tool    ON tool_outputs(tool);
"""


@dataclass
class ToolOutputRef:
    """Pointer to a persisted tool output, returned by ``ToolOutputStore.store``."""
    call_id: str
    run_id: str
    engagement_id: str
    tool: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_path: str
    stderr_path: str
    artifacts_dir: str
    stdout_compressed: bool
    stderr_compressed: bool
    truncated_in_memory: bool
    returncode: int
    duration_seconds: float
    created_at: str

    def uri(self, kind: str = "stdout") -> str:
        """Canonical MCP resource URI for this output stream."""
        if kind not in ("stdout", "stderr", "artifacts"):
            raise ValueError(f"unknown kind: {kind}")
        return f"sap://run/{self.run_id}/output/{self.call_id}/{kind}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stdout_uri"] = self.uri("stdout")
        d["stderr_uri"] = self.uri("stderr")
        d["artifacts_uri"] = self.uri("artifacts")
        return d


def _now_iso() -> str:
    return _sap_utcnow().isoformat(timespec="seconds")


def _is_gzip(path: Path) -> bool:
    return path.suffix == ".gz"


class ToolOutputStore:
    """Hybrid persistence: SQLite metadata index + filesystem blobs."""

    def __init__(
        self,
        db_path: str | None = None,
        *,
        sessions_root: Path | None = None,
        gzip_threshold_bytes: int = _GZIP_THRESHOLD_BYTES,
    ):
        self._db_path = str(db_path) if db_path else str(assessments_db_path())
        self._sessions_root = Path(sessions_root) if sessions_root else sessions_dir()
        self._gzip_threshold = gzip_threshold_bytes
        self._initialized = False
        self._init_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def init(self) -> None:
        async with self._init_lock:
            if self._initialized:
                return
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
            async with aiosqlite.connect(self._db_path) as db:
                await db.executescript(SCHEMA)
                await db.commit()
            self._initialized = True

    async def _ensure_init(self) -> None:
        if not self._initialized:
            await self.init()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def run_dir(self, run_id: str) -> Path:
        return self._sessions_root / "runs" / run_id

    def call_dir(self, run_id: str, call_id: str) -> Path:
        return self.run_dir(run_id) / "tool_outputs" / call_id

    def artifacts_dir(self, run_id: str, call_id: str) -> Path:
        return self.call_dir(run_id, call_id) / "artifacts"

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    @staticmethod
    def new_call_id() -> str:
        return f"call_{uuid.uuid4().hex[:16]}"

    def allocate(self, run_id: str, call_id: str | None = None) -> tuple[str, Path]:
        """Pre-allocate a call_id and create its artifacts directory.

        Used when a tool needs to write structured output to a known location
        BEFORE execution (e.g. ``nmap -oA``). The returned path is guaranteed
        to exist and to be writable by the current process. The ToolOutputStore
        will later overwrite ``meta.json``/``stdout.bin``/``stderr.bin`` in the
        same call directory when ``store(..., call_id=...)`` is invoked.
        """
        cid = call_id or self.new_call_id()
        adir = self.artifacts_dir(run_id, cid)
        adir.mkdir(parents=True, exist_ok=True)
        return cid, adir

    async def store(
        self,
        *,
        run_id: str,
        tool: str,
        command_redacted: str,
        stdout: bytes,
        stderr: bytes,
        returncode: int,
        duration_seconds: float,
        engagement_id: str = "",
        target: str = "",
        phase: str = "",
        truncated_in_memory: bool = False,
        started_at: str | None = None,
        ended_at: str | None = None,
        call_id: str | None = None,
        meta_extra: dict[str, Any] | None = None,
    ) -> ToolOutputRef:
        """Persist a tool output. Returns the canonical reference.

        Files are written first (durable), then a row is inserted in the
        SQLite index.
        """
        await self._ensure_init()
        cid = call_id or self.new_call_id()
        cdir = self.call_dir(run_id, cid)
        adir = self.artifacts_dir(run_id, cid)
        adir.mkdir(parents=True, exist_ok=True)

        # Write blobs in a worker thread (gzip can be CPU-bound).
        stdout_path, stdout_compressed = await asyncio.to_thread(
            self._write_blob, cdir / "stdout.bin", stdout
        )
        stderr_path, stderr_compressed = await asyncio.to_thread(
            self._write_blob, cdir / "stderr.bin", stderr
        )

        # meta.json sidecar (human-readable, in addition to SQLite).
        meta: dict[str, Any] = {
            "call_id": cid,
            "run_id": run_id,
            "engagement_id": engagement_id,
            "tool": tool,
            "command_redacted": command_redacted,
            "target": target,
            "phase": phase,
            "returncode": returncode,
            "duration_seconds": duration_seconds,
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_path": str(stdout_path.relative_to(self._sessions_root)),
            "stderr_path": str(stderr_path.relative_to(self._sessions_root)),
            "artifacts_dir": str(adir.relative_to(self._sessions_root)),
            "stdout_compressed": stdout_compressed,
            "stderr_compressed": stderr_compressed,
            "truncated_in_memory": truncated_in_memory,
            "started_at": started_at or _now_iso(),
            "ended_at": ended_at or _now_iso(),
            "created_at": _now_iso(),
        }
        if meta_extra:
            meta["extra"] = meta_extra
        await asyncio.to_thread(
            (cdir / "meta.json").write_text,
            json.dumps(meta, indent=2),
            "utf-8",
        )

        # SQLite index
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO tool_outputs (
                    call_id, run_id, engagement_id, tool, command_redacted,
                    target, phase, returncode, duration_seconds,
                    stdout_bytes, stderr_bytes,
                    stdout_path, stderr_path, artifacts_dir,
                    stdout_compressed, stderr_compressed,
                    truncated_in_memory,
                    started_at, ended_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cid, run_id, engagement_id, tool, command_redacted,
                    target, phase, returncode, duration_seconds,
                    len(stdout), len(stderr),
                    meta["stdout_path"], meta["stderr_path"], meta["artifacts_dir"],
                    int(stdout_compressed), int(stderr_compressed),
                    int(truncated_in_memory),
                    meta["started_at"], meta["ended_at"], meta["created_at"],
                ),
            )
            await db.commit()

        return ToolOutputRef(
            call_id=cid,
            run_id=run_id,
            engagement_id=engagement_id,
            tool=tool,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            stdout_path=str(meta["stdout_path"]),
            stderr_path=str(meta["stderr_path"]),
            artifacts_dir=str(meta["artifacts_dir"]),
            stdout_compressed=stdout_compressed,
            stderr_compressed=stderr_compressed,
            truncated_in_memory=truncated_in_memory,
            returncode=returncode,
            duration_seconds=duration_seconds,
            created_at=str(meta["created_at"]),
        )

    def _write_blob(self, path: Path, data: bytes) -> tuple[Path, bool]:
        """Write *data* to *path*, gzipping when above threshold."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if len(data) >= self._gzip_threshold:
            gz_path = path.with_suffix(path.suffix + ".gz")
            with gzip.open(gz_path, "wb", compresslevel=6) as f:
                f.write(data)
            try:
                os.chmod(gz_path, 0o600)
            except OSError:
                pass
            return gz_path, True
        path.write_bytes(data)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path, False

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    async def read(
        self,
        call_id: str,
        kind: str = "stdout",
        *,
        head: int | None = None,
        tail: int | None = None,
        offset: int | None = None,
        length: int | None = None,
    ) -> bytes:
        """Read bytes from a stored output.

        ``head``/``tail`` return the first/last N bytes respectively.
        ``offset``/``length`` perform an arbitrary range read. When all are
        ``None`` the full content is returned.
        """
        if kind not in ("stdout", "stderr"):
            raise ValueError(f"unsupported kind: {kind}")
        await self._ensure_init()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                # noqa: S608 — `kind` is validated to {"stdout","stderr"} before reaching here
                f"SELECT {kind}_path AS p, {kind}_compressed AS c, {kind}_bytes AS n "  # noqa: S608
                f"FROM tool_outputs WHERE call_id = ?",
                (call_id,),
            ) as cur:
                row = await cur.fetchone()
        if not row:
            raise KeyError(f"no tool_output for call_id={call_id}")
        rel = row["p"]
        if not rel:
            return b""
        path = self._sessions_root / rel
        return await asyncio.to_thread(
            self._read_blob, path, bool(row["c"]), int(row["n"]),
            head, tail, offset, length,
        )

    @staticmethod
    def _read_blob(
        path: Path,
        compressed: bool,
        total: int,
        head: int | None,
        tail: int | None,
        offset: int | None,
        length: int | None,
    ) -> bytes:
        if not path.exists():
            return b""
        opener = (lambda: gzip.open(path, "rb")) if compressed else (lambda: open(path, "rb"))
        if head is not None and tail is None and offset is None:
            with opener() as f:
                return f.read(int(head))
        if tail is not None and head is None and offset is None:
            n = int(tail)
            if compressed:
                with opener() as f:
                    data = f.read()
                return data[-n:]
            with open(path, "rb") as f:
                size = path.stat().st_size
                f.seek(max(0, size - n))
                return f.read()
        if offset is not None or length is not None:
            off = int(offset or 0)
            ln = int(length) if length is not None else total
            if compressed:
                with opener() as f:
                    if off:
                        f.read(off)
                    return f.read(ln)
            with open(path, "rb") as f:
                f.seek(off)
                return f.read(ln)
        # full read
        with opener() as f:
            return f.read()

    async def get(self, call_id: str) -> ToolOutputRef | None:
        await self._ensure_init()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM tool_outputs WHERE call_id = ?", (call_id,)
            ) as cur:
                row = await cur.fetchone()
        return self._row_to_ref(row) if row else None

    async def list(
        self,
        *,
        run_id: str | None = None,
        engagement_id: str | None = None,
        tool: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[ToolOutputRef]:
        await self._ensure_init()
        clauses: list[str] = []
        params: list[Any] = []
        if run_id is not None:
            clauses.append("run_id = ?")
            params.append(run_id)
        if engagement_id is not None:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if tool is not None:
            clauses.append("tool = ?")
            params.append(tool)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        # noqa: S608 — `clauses` are internal hardcoded templates ("run_id = ?" etc.)
        sql = (
            "SELECT * FROM tool_outputs" + where  # noqa: S608
            + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        )
        params.extend([int(limit), int(offset)])
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(sql, params) as cur:
                rows = await cur.fetchall()
        return [self._row_to_ref(r) for r in rows]

    @staticmethod
    def _row_to_ref(row: aiosqlite.Row) -> ToolOutputRef:
        return ToolOutputRef(
            call_id=row["call_id"],
            run_id=row["run_id"],
            engagement_id=row["engagement_id"] or "",
            tool=row["tool"],
            stdout_bytes=int(row["stdout_bytes"] or 0),
            stderr_bytes=int(row["stderr_bytes"] or 0),
            stdout_path=row["stdout_path"] or "",
            stderr_path=row["stderr_path"] or "",
            artifacts_dir=row["artifacts_dir"] or "",
            stdout_compressed=bool(row["stdout_compressed"]),
            stderr_compressed=bool(row["stderr_compressed"]),
            truncated_in_memory=bool(row["truncated_in_memory"]),
            returncode=int(row["returncode"]) if row["returncode"] is not None else -1,
            duration_seconds=float(row["duration_seconds"] or 0.0),
            created_at=row["created_at"] or "",
        )

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def list_artifacts(self, ref: ToolOutputRef) -> builtins.list[Path]:
        adir = self._sessions_root / ref.artifacts_dir
        if not adir.exists():
            return []
        return sorted(p for p in adir.rglob("*") if p.is_file())

    # ------------------------------------------------------------------
    # Garbage Collection
    # ------------------------------------------------------------------

    async def gc(
        self,
        *,
        retention_days: int = _DEFAULT_RETENTION_DAYS,
        keep_engagement_ids: set[str] | None = None,
        now: datetime | None = None,
        dry_run: bool = False,
    ) -> dict[str, int]:
        """Delete tool_outputs older than ``retention_days``.

        ``keep_engagement_ids`` excludes specific engagements from cleanup
        (e.g., still-active ones). Returns counters.
        """
        await self._ensure_init()
        cutoff = (now or _sap_utcnow()) - timedelta(days=int(retention_days))
        cutoff_iso = cutoff.isoformat(timespec="seconds")
        keep = keep_engagement_ids or set()

        deleted_rows = 0
        deleted_dirs = 0
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT call_id, run_id, engagement_id FROM tool_outputs "
                "WHERE created_at < ?",
                (cutoff_iso,),
            ) as cur:
                rows = await cur.fetchall()
            victims = [
                (r["call_id"], r["run_id"]) for r in rows
                if (r["engagement_id"] or "") not in keep
            ]
            if dry_run:
                return {"candidates": len(victims), "deleted_rows": 0, "deleted_dirs": 0}
            for cid, rid in victims:
                # Filesystem first, DB second — never orphan a row.
                cdir = self.call_dir(rid, cid)
                if cdir.exists():
                    try:
                        await asyncio.to_thread(shutil.rmtree, cdir)
                        deleted_dirs += 1
                    except Exception as exc:  # pragma: no cover
                        _log.error("gc rmtree failed for %s: %s", cdir, exc)
                        continue
                await db.execute(
                    "DELETE FROM tool_outputs WHERE call_id = ?", (cid,)
                )
                deleted_rows += 1
            await db.commit()

        return {
            "candidates": len(victims),
            "deleted_rows": deleted_rows,
            "deleted_dirs": deleted_dirs,
        }


# ─────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────

_STORE: ToolOutputStore | None = None


def get_tool_output_store() -> ToolOutputStore:
    global _STORE
    if _STORE is None:
        _STORE = ToolOutputStore()
    return _STORE


def reset_tool_output_store() -> None:
    """Reset the module-level singleton. Used by tests."""
    global _STORE
    _STORE = None
