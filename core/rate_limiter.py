"""
core/rate_limiter.py — Cross-process rate limiter + lockout (P1.7).

A small SQLite-backed limiter shared by every uvicorn worker / process in the
SAP stack. Used to harden brute-force surfaces such as ``/api/auth/login`` and
``/api/sudo/unlock``. Default policy:

    * Sliding window of N attempts in W seconds → 429.
    * After M consecutive failures from the same key → lockout for L seconds.

Keys are opaque strings (e.g. ``"login:127.0.0.1"``). The DB lives under
``$XDG_STATE_HOME/sap/rate_limit.sqlite`` and is created on first use with
``mode 0600`` perms (the parent directory is honored as-is).

Notes:
* SQLite is fine for the expected QPS (single-host workstation install) and
  removes the need for an external Redis dependency.
* All operations are wrapped in a short busy_timeout so concurrent writers do
  not raise ``database is locked``.
* No PII is persisted: only the hashed key, attempt count, last_ts, and
  optional locked_until.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


def _db_path() -> Path:
    base = os.environ.get("SAP_RATE_LIMIT_DB")
    if base:
        return Path(base)
    state = os.environ.get("SAP_STATE_DIR") or os.environ.get("XDG_STATE_HOME") or ""
    if state and "sap" not in Path(state).name:
        state = str(Path(state) / "sap")
    if not state:
        state = str(Path.home() / ".local" / "state" / "sap")
    Path(state).mkdir(parents=True, exist_ok=True)
    return Path(state) / "rate_limit.sqlite"


def _key_hash(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    retry_after_s: int
    reason: str  # "ok" | "rate" | "lockout"


class RateLimiter:
    """SQLite-backed sliding-window limiter with lockout."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or _db_path()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(str(self.db_path), timeout=2.0, isolation_level=None)
        c.execute("PRAGMA busy_timeout=2000")
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def _init_db(self) -> None:
        try:
            with self._conn() as c:
                c.execute(
                    """CREATE TABLE IF NOT EXISTS attempts (
                        khash TEXT PRIMARY KEY,
                        count INTEGER NOT NULL,
                        first_ts REAL NOT NULL,
                        last_ts  REAL NOT NULL,
                        failures INTEGER NOT NULL DEFAULT 0,
                        locked_until REAL NOT NULL DEFAULT 0
                    )"""
                )
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
        except sqlite3.Error:
            # Best effort: a hostile FS (read-only) shouldn't crash the app.
            pass

    def check(
        self,
        key: str,
        *,
        window_s: int = 60,
        max_attempts: int = 5,
        lockout_s: int = 900,
        max_failures: int = 10,
    ) -> RateLimitResult:
        """Record an attempt; return decision.

        ``window_s`` / ``max_attempts``: sliding-window throttle (per call).
        ``max_failures`` / ``lockout_s``: long-term lockout once exceeded.

        The caller is expected to invoke ``record_failure(key)`` after a
        verified credential failure (so successes do not count against the
        lockout budget) and ``record_success(key)`` after a verified success
        (resets failures + counter).
        """
        khash = _key_hash(key)
        now = time.time()
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT count, first_ts, locked_until, failures FROM attempts "
                    "WHERE khash = ?",
                    (khash,),
                ).fetchone()
                if row:
                    count, first_ts, locked_until, failures = row
                else:
                    count = 0
                    first_ts = now
                    locked_until = 0.0
                    failures = 0

                if locked_until and now < locked_until:
                    return RateLimitResult(False, int(locked_until - now) + 1, "lockout")

                # Reset window if expired.
                if (now - first_ts) > window_s:
                    count = 0
                    first_ts = now

                count += 1
                if count > max_attempts:
                    retry = int(window_s - (now - first_ts)) + 1
                    c.execute(
                        "INSERT INTO attempts(khash,count,first_ts,last_ts,failures,locked_until) "
                        "VALUES(?,?,?,?,?,?) "
                        "ON CONFLICT(khash) DO UPDATE SET count=excluded.count, "
                        "last_ts=excluded.last_ts",
                        (khash, count, first_ts, now, failures, locked_until),
                    )
                    return RateLimitResult(False, max(retry, 1), "rate")

                c.execute(
                    "INSERT INTO attempts(khash,count,first_ts,last_ts,failures,locked_until) "
                    "VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(khash) DO UPDATE SET count=excluded.count, "
                    "first_ts=excluded.first_ts, last_ts=excluded.last_ts",
                    (khash, count, first_ts, now, failures, locked_until),
                )
        except sqlite3.Error:
            # Fail-open on DB errors so a corrupt cache cannot lock the user
            # out forever. Audit log will catch the underlying issue.
            return RateLimitResult(True, 0, "ok")
        return RateLimitResult(True, 0, "ok")

    def record_failure(self, key: str, *, max_failures: int = 10, lockout_s: int = 900) -> None:
        khash = _key_hash(key)
        now = time.time()
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT failures FROM attempts WHERE khash = ?", (khash,)
                ).fetchone()
                failures = (row[0] if row else 0) + 1
                locked_until = now + lockout_s if failures >= max_failures else 0.0
                c.execute(
                    "INSERT INTO attempts(khash,count,first_ts,last_ts,failures,locked_until) "
                    "VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(khash) DO UPDATE SET failures=excluded.failures, "
                    "locked_until=excluded.locked_until, last_ts=excluded.last_ts",
                    (khash, 1, now, now, failures, locked_until),
                )
        except sqlite3.Error:
            pass

    def record_success(self, key: str) -> None:
        khash = _key_hash(key)
        try:
            with self._conn() as c:
                c.execute(
                    "UPDATE attempts SET failures=0, count=0, locked_until=0 "
                    "WHERE khash = ?",
                    (khash,),
                )
        except sqlite3.Error:
            pass


_LIMITER: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _LIMITER
    if _LIMITER is None:
        _LIMITER = RateLimiter()
    return _LIMITER


def reset_rate_limiter_for_tests() -> None:
    """Test helper: drop the singleton so a new ``SAP_RATE_LIMIT_DB`` env is honored."""
    global _LIMITER
    _LIMITER = None
