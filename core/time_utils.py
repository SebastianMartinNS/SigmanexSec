"""
core/time_utils.py — Timezone-correct helpers for timestamps.

Centralises the replacement of the deprecated ``datetime.utcnow()`` so the
rest of the code can stay simple. Returns a naive UTC ``datetime`` to remain
byte-compatible with previously stored timestamps (SQLite columns, audit log
strings) which are compared lexicographically.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive ``datetime`` (no tzinfo).

    Equivalent to the deprecated ``datetime.utcnow()`` but built from a
    timezone-aware ``datetime.now(timezone.utc)`` and then stripped of its
    tzinfo so that ``.isoformat()`` produces the same legacy-format string
    (no ``+00:00`` suffix). This preserves SQLite ordering semantics for
    rows written before this change.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_iso(timespec: str = "seconds") -> str:
    """Convenience: ISO-formatted naive UTC timestamp."""
    return utcnow().isoformat(timespec=timespec)
