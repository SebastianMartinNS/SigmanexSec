"""Tests for the log-rotation half of `core/storage_gc._rotate_logs`."""

from __future__ import annotations

import gzip
import os
import time
from datetime import timedelta
from pathlib import Path

from core.storage_gc import _AUDIT_EXCLUDES, _rotate_logs, _rotate_one


def _write(path: Path, size_bytes: int = 0, content: bytes | None = None) -> Path:
    if content is None:
        content = b"x" * size_bytes
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def test_rotate_logs_skips_audit_jsonl(tmp_path):
    """audit.jsonl must NEVER be touched by this routine — it belongs to
    core/audit_log.py which preserves the BLAKE2b chain across its own
    rotation. The .head mirror does not match any glob pattern and so is
    not considered at all (which is also safe)."""
    _write(tmp_path / "audit.jsonl", size_bytes=200 * 1024 * 1024)
    _write(tmp_path / "audit.jsonl.head", size_bytes=200 * 1024 * 1024)

    stats = _rotate_logs(
        log_dir=tmp_path,
        size_threshold_bytes=1024,
        max_age=timedelta(days=14),
        keep=2,
    )
    assert stats["rotated"] == 0
    # audit.jsonl was globbed and rejected via the exclude set.
    assert stats["skipped"] == 1
    assert "audit.jsonl" in _AUDIT_EXCLUDES and "audit.jsonl.head" in _AUDIT_EXCLUDES
    # The originals are still untouched.
    assert (tmp_path / "audit.jsonl").stat().st_size == 200 * 1024 * 1024
    assert (tmp_path / "audit.jsonl.head").stat().st_size == 200 * 1024 * 1024


def test_rotate_logs_rotates_only_files_over_size_threshold(tmp_path):
    big = _write(tmp_path / "dashboard.log", size_bytes=2 * 1024 * 1024)
    small = _write(tmp_path / "ws.log", size_bytes=1024)

    stats = _rotate_logs(
        log_dir=tmp_path,
        size_threshold_bytes=1024 * 1024,  # 1 MiB
        max_age=timedelta(days=14),
        keep=5,
    )
    assert stats["rotated"] == 1
    assert big.stat().st_size == 0  # truncated in place
    assert small.read_bytes() == b"x" * 1024  # untouched
    archives = list(tmp_path.glob("dashboard.log.*.gz"))
    assert len(archives) == 1
    # Round-trip the archive to confirm gzip integrity.
    with gzip.open(archives[0], "rb") as gz:
        assert gz.read() == b"x" * 2 * 1024 * 1024


def test_rotate_logs_rotates_files_older_than_max_age(tmp_path):
    aged = _write(tmp_path / "old.log", size_bytes=64)
    old_mtime = time.time() - timedelta(days=30).total_seconds()
    os.utime(aged, (old_mtime, old_mtime))

    stats = _rotate_logs(
        log_dir=tmp_path,
        size_threshold_bytes=10 * 1024 * 1024,
        max_age=timedelta(days=14),
        keep=5,
    )
    assert stats["rotated"] == 1
    assert aged.stat().st_size == 0
    archives = list(tmp_path.glob("old.log.*.gz"))
    assert len(archives) == 1


def test_rotate_logs_trims_history_to_keep_count(tmp_path):
    # Seed five stale gzipped archives with monotonically increasing mtimes.
    for i in range(5):
        f = tmp_path / f"foo.log.20260{i+1}01T000000Z.gz"
        f.write_bytes(b"\x1f\x8b")  # minimal gzip header bytes
        ts = time.time() - (10 - i) * 86400
        os.utime(f, (ts, ts))

    live = _write(tmp_path / "foo.log", size_bytes=2 * 1024 * 1024)

    _rotate_logs(
        log_dir=tmp_path,
        size_threshold_bytes=1024 * 1024,
        max_age=timedelta(days=14),
        keep=3,
    )
    # The freshly rotated archive plus the two most recent of the five
    # seeded archives = 3 retained.
    archives = sorted(tmp_path.glob("foo.log.*.gz"))
    assert len(archives) == 3
    # Live file truncated.
    assert live.stat().st_size == 0


def test_rotate_logs_no_op_when_dir_missing(tmp_path):
    missing = tmp_path / "no-such-dir"
    stats = _rotate_logs(log_dir=missing)
    assert stats == {"considered": 0, "rotated": 0, "skipped": 0}


def test_rotate_one_skips_empty_files(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_bytes(b"")
    assert _rotate_one(empty, keep=5) is False
    # No archive created.
    assert not list(tmp_path.glob("empty.log.*.gz"))


def test_rotate_logs_handles_multiple_patterns(tmp_path):
    """*.log, *.jsonl, *.out, *.err — all should be candidates."""
    _write(tmp_path / "service.log", size_bytes=2 * 1024 * 1024)
    _write(tmp_path / "events.jsonl", size_bytes=2 * 1024 * 1024)
    _write(tmp_path / "stdout.out", size_bytes=2 * 1024 * 1024)
    _write(tmp_path / "stderr.err", size_bytes=2 * 1024 * 1024)

    stats = _rotate_logs(
        log_dir=tmp_path,
        size_threshold_bytes=1024 * 1024,
        max_age=timedelta(days=14),
        keep=5,
    )
    assert stats["rotated"] == 4
    assert stats["considered"] == 4


def test_rotate_logs_respects_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_LOG_ROTATE_DIR", str(tmp_path))
    monkeypatch.setenv("SAP_LOG_ROTATE_SIZE_MB", "1")
    monkeypatch.setenv("SAP_LOG_ROTATE_AGE_DAYS", "30")
    monkeypatch.setenv("SAP_LOG_ROTATE_KEEP", "2")

    _write(tmp_path / "x.log", size_bytes=2 * 1024 * 1024)
    stats = _rotate_logs()
    assert stats["rotated"] == 1
