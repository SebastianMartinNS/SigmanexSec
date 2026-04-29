"""SQLite-backed store for memory subsystems.

Tables:
  - core_blocks: editable named memory blocks per engagement
  - messages:    full conversation history (recall) + FTS5 mirror
  - archival:    long-term passages with embeddings (BLOB) and metadata
  - run_state:   small key/value scratch per run (e.g. summary cursor)

Embeddings are stored as raw little-endian float32 BLOBs. Search is done
in-process (cosine over a candidate set filtered by SQL) — no daemons.
For workloads beyond ~100k passages per engagement, swap in sqlite-vec
by setting SAP_USE_SQLITE_VEC=1 (left as a hook, not enabled by default).
"""
from __future__ import annotations

import asyncio
import struct
import time
from pathlib import Path
from typing import Optional

import aiosqlite

from core.paths import memory_db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS core_blocks (
    engagement_id TEXT NOT NULL,
    label         TEXT NOT NULL,
    value         TEXT NOT NULL DEFAULT '',
    max_chars     INTEGER NOT NULL DEFAULT 2000,
    updated_at    REAL NOT NULL,
    PRIMARY KEY (engagement_id, label)
);

CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    run_id        TEXT,
    seq           INTEGER NOT NULL,
    ts            REAL NOT NULL,
    role          TEXT NOT NULL,
    content       TEXT NOT NULL,
    tool_call_id  TEXT,
    tool_name     TEXT,
    summarized    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_eng_seq
    ON messages(engagement_id, seq);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
    USING fts5(content, role, engagement_id UNINDEXED, message_id UNINDEXED);

CREATE TABLE IF NOT EXISTS archival (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    ts            REAL NOT NULL,
    source        TEXT,
    text          TEXT NOT NULL,
    embedding     BLOB,
    embedding_dim INTEGER NOT NULL DEFAULT 0,
    metadata      TEXT
);
CREATE INDEX IF NOT EXISTS idx_archival_eng ON archival(engagement_id);

CREATE TABLE IF NOT EXISTS run_state (
    engagement_id TEXT NOT NULL,
    run_id        TEXT NOT NULL,
    key           TEXT NOT NULL,
    value         TEXT NOT NULL,
    PRIMARY KEY (engagement_id, run_id, key)
);
"""


def pack_embedding(vec: list[float]) -> bytes:
    return struct.pack(f"<{len(vec)}f", *vec)


def unpack_embedding(blob: bytes, dim: int) -> list[float]:
    if not blob or dim <= 0:
        return []
    try:
        return list(struct.unpack(f"<{dim}f", blob[: dim * 4]))
    except struct.error:
        return []


class MemoryStore:
    """Async facade around aiosqlite for the memory subsystem."""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = str(db_path) if db_path else str(memory_db_path())
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def init(self) -> None:
        async with self._init_lock:
            if self._initialized:
                return
            async with aiosqlite.connect(self._db_path) as db:
                await db.executescript(_SCHEMA)
                await db.commit()
            self._initialized = True

    # ---------------- core blocks ----------------

    async def upsert_block(
        self, engagement_id: str, label: str, value: str, max_chars: int = 2000
    ) -> None:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO core_blocks(engagement_id,label,value,max_chars,updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(engagement_id,label) DO UPDATE SET
                     value=excluded.value,
                     max_chars=excluded.max_chars,
                     updated_at=excluded.updated_at""",
                (engagement_id, label, value[:max_chars], max_chars, time.time()),
            )
            await db.commit()

    async def get_block(
        self, engagement_id: str, label: str
    ) -> Optional[tuple[str, int]]:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT value,max_chars FROM core_blocks WHERE engagement_id=? AND label=?",
                (engagement_id, label),
            ) as cur:
                row = await cur.fetchone()
        return (row[0], row[1]) if row else None

    async def list_blocks(self, engagement_id: str) -> list[tuple[str, str, int]]:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT label,value,max_chars FROM core_blocks WHERE engagement_id=? ORDER BY label",
                (engagement_id,),
            ) as cur:
                rows = await cur.fetchall()
        return [(r[0], r[1], r[2]) for r in rows]

    # ---------------- messages / recall ----------------

    async def append_message(
        self,
        engagement_id: str,
        run_id: str,
        role: str,
        content: str,
        *,
        tool_call_id: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> int:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM messages WHERE engagement_id=?",
                (engagement_id,),
            ) as cur:
                row = await cur.fetchone()
            seq = int(row[0]) if row else 0
            cur = await db.execute(
                """INSERT INTO messages(engagement_id,run_id,seq,ts,role,content,tool_call_id,tool_name)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (engagement_id, run_id, seq, time.time(), role, content, tool_call_id, tool_name),
            )
            msg_id = cur.lastrowid
            await db.execute(
                "INSERT INTO messages_fts(content,role,engagement_id,message_id) VALUES(?,?,?,?)",
                (content, role, engagement_id, msg_id),
            )
            await db.commit()
        return msg_id

    async def get_messages_since(
        self, engagement_id: str, since_seq: int
    ) -> list[dict]:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT id,seq,role,content,tool_call_id,tool_name,summarized
                   FROM messages WHERE engagement_id=? AND seq>=?
                   ORDER BY seq ASC""",
                (engagement_id, since_seq),
            ) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def mark_summarized(self, ids: list[int]) -> None:
        if not ids:
            return
        await self.init()
        placeholders = ",".join("?" * len(ids))
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                f"UPDATE messages SET summarized=1 WHERE id IN ({placeholders})", ids
            )
            await db.commit()

    async def fts_search(
        self,
        engagement_id: str,
        query: str,
        *,
        k: int = 10,
        role: Optional[str] = None,
    ) -> list[dict]:
        await self.init()
        sql = (
            "SELECT m.id, m.seq, m.role, m.content, m.ts FROM messages_fts f "
            "JOIN messages m ON m.id = f.message_id "
            "WHERE f.engagement_id=? AND messages_fts MATCH ?"
        )
        params: list = [engagement_id, query]
        if role:
            sql += " AND m.role=?"
            params.append(role)
        sql += " ORDER BY rank LIMIT ?"
        params.append(k)
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            try:
                async with db.execute(sql, params) as cur:
                    rows = await cur.fetchall()
            except aiosqlite.OperationalError:
                # FTS5 not compiled in — degrade to LIKE
                like = f"%{query}%"
                async with db.execute(
                    "SELECT id,seq,role,content,ts FROM messages "
                    "WHERE engagement_id=? AND content LIKE ? "
                    + ("AND role=? " if role else "")
                    + "ORDER BY seq DESC LIMIT ?",
                    [engagement_id, like] + ([role] if role else []) + [k],
                ) as cur:
                    rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # ---------------- archival ----------------

    async def insert_archival(
        self,
        engagement_id: str,
        text: str,
        embedding: list[float],
        *,
        source: Optional[str] = None,
        metadata: Optional[str] = None,
    ) -> int:
        await self.init()
        blob = pack_embedding(embedding) if embedding else None
        dim = len(embedding)
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute(
                """INSERT INTO archival(engagement_id,ts,source,text,embedding,embedding_dim,metadata)
                   VALUES(?,?,?,?,?,?,?)""",
                (engagement_id, time.time(), source, text, blob, dim, metadata),
            )
            await db.commit()
            return cur.lastrowid

    async def list_archival(
        self, engagement_id: Optional[str] = None, limit: int = 5000
    ) -> list[dict]:
        await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            if engagement_id:
                cur = await db.execute(
                    "SELECT id,ts,source,text,embedding,embedding_dim,metadata "
                    "FROM archival WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
                    (engagement_id, limit),
                )
            else:
                cur = await db.execute(
                    "SELECT id,ts,source,text,embedding,embedding_dim,metadata "
                    "FROM archival ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            async with cur as c:
                rows = await c.fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["embedding"] = unpack_embedding(d["embedding"], d["embedding_dim"])
            out.append(d)
        return out
