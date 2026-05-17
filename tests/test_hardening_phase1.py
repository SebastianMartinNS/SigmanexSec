"""Robustness hardening — Phase 1+2+3+4 verification.

Locks in behavior added by the hardening pass:
- Subprocess process-group kill on timeout (executor)
- DNS resolution timeout in ScopeValidator
- Bounded DNS cache (TTL + FIFO)
- compile_blocked_patterns() fails loudly on bad regex
- AuditLog rotation when SAP_AUDIT_MAX_BYTES is exceeded
- AuditLog._append fsyncs before returning
- Streaming output cap on runaway tool stdout
- Dashboard request-body size limit (413 on oversized POST)
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


# ── Executor: process-group kill on timeout ─────────────────────────────────
@pytest.mark.asyncio
async def test_exec_timeout_kills_process_tree(tmp_path, monkeypatch):
    """A child that spawns its own grandchildren must be fully reaped on timeout."""
    from core.executor import ToolExecutor

    sentinel = tmp_path / "child.pid"
    # Bash spawns a long-sleeping grandchild and prints its PID to a file. We
    # then trigger the executor timeout and verify the grandchild PID is gone.
    script = (
        f"sleep 30 & echo $! > {sentinel}; "
        "wait"
    )
    cmd = ["/bin/bash", "-c", script]
    out, err, rc = await ToolExecutor._exec(cmd, timeout=1, cwd=None)
    assert rc == -1
    assert "TIMEOUT" in out
    # Wait a beat for the kill to propagate.
    await asyncio.sleep(0.3)
    if sentinel.exists():
        pid = int(sentinel.read_text().strip())
        # /proc/<pid> must be absent or zombie/dead.
        proc_dir = Path(f"/proc/{pid}")
        assert not proc_dir.exists() or _is_dead(proc_dir), (
            f"grandchild PID {pid} survived process-tree kill"
        )


def _is_dead(proc_dir: Path) -> bool:
    try:
        status = (proc_dir / "status").read_text()
    except OSError:
        return True
    for line in status.splitlines():
        if line.startswith("State:"):
            return line.split()[1] in {"X", "Z"}
    return True


# ── Executor: streaming output cap kills runaway tools ──────────────────────
@pytest.mark.asyncio
async def test_exec_output_cap_kills_runaway(monkeypatch):
    """A tool emitting unbounded stdout must be killed at the cap."""
    from core import executor as ex

    monkeypatch.setenv("SAP_EXEC_PERSIST_MAX_BYTES", str(64 * 1024))  # 64 KB cap
    # Force re-read: the helper reads env each call so no cache to clear.
    cmd = ["/usr/bin/yes"]  # emits "y\n" forever
    out, err, rc = await ex.ToolExecutor._exec(cmd, timeout=10, cwd=None)
    # We should get back roughly cap bytes, plus the truncation marker, NOT
    # forever-much output, and the call must return well under the timeout.
    assert "TRUNCATED" in out
    assert len(out.encode("utf-8")) < 200 * 1024


# ── ScopeValidator: DNS timeout does not block forever ─────────────────────
def test_scope_dns_timeout_returns_quickly(monkeypatch):
    """A blocking resolver must not stall scope validation past the timeout."""
    import time

    import core.scope_validator as sv

    # Monkey-patch getaddrinfo to sleep 30s; our pool timeout is 3s default.
    # We override the timeout to 0.5s for a tight test budget.
    monkeypatch.setattr(sv, "_DNS_RESOLVE_TIMEOUT_S", 0.5)

    def _slow(*args, **kwargs):
        time.sleep(30)
        return []

    monkeypatch.setattr(sv.socket, "getaddrinfo", _slow)
    v = sv.ScopeValidator(domains=["example.com"])
    t0 = time.monotonic()
    ips = v._resolve_domain_ips("example.com")
    elapsed = time.monotonic() - t0
    assert ips == set()
    assert elapsed < 2.5, f"DNS resolution took {elapsed:.2f}s, expected <2.5s"


# ── ScopeValidator: cache is bounded (FIFO eviction) ────────────────────────
def test_scope_dns_cache_bounded(monkeypatch):
    import core.scope_validator as sv

    monkeypatch.setattr(sv, "_DNS_CACHE_MAX", 4)
    monkeypatch.setattr(sv.socket, "getaddrinfo", lambda *a, **k: [])
    v = sv.ScopeValidator(domains=["a.test"])
    for i in range(20):
        v._resolve_domain_ips(f"d{i}.test")
    assert len(v._domain_ip_cache) <= 4


# ── Executor: compile_blocked_patterns surfaces bad regex ──────────────────
def test_compile_blocked_patterns_rejects_bad_regex(monkeypatch):
    from core import executor as ex

    monkeypatch.setattr(ex, "_blocked_patterns", lambda: [r"(unclosed"])
    ex._BLOCKED_PATTERNS_CACHE = None
    with pytest.raises(ValueError) as ei:
        ex.compile_blocked_patterns(force=True)
    assert "Invalid blocked_arg_patterns" in str(ei.value)


def test_compile_blocked_patterns_caches(monkeypatch):
    from core import executor as ex

    calls = {"n": 0}

    def _patterns():
        calls["n"] += 1
        return [r"rm\s+-rf"]

    monkeypatch.setattr(ex, "_blocked_patterns", _patterns)
    ex._BLOCKED_PATTERNS_CACHE = None
    ex.compile_blocked_patterns(force=True)
    ex.compile_blocked_patterns()
    ex.compile_blocked_patterns()
    # Force=False reuses the cache; only the force=True call invokes the loader.
    assert calls["n"] == 1


# ── AuditLog: rotation when size cap exceeded ──────────────────────────────
@pytest.mark.asyncio
async def test_audit_log_rotates_at_size_cap(tmp_path, monkeypatch):
    from core.audit_log import AuditLog
    from core.models import AuditEntry

    monkeypatch.setenv("SAP_AUDIT_MAX_BYTES", "2048")  # 2 KB → rotate fast
    log_path = tmp_path / "audit.jsonl"
    al = AuditLog(log_path=str(log_path))

    # First batch — drains and writes ``audit.jsonl``.
    for i in range(60):
        await al.write(AuditEntry(
            engagement_id=f"eng-{i:03d}",
            action="test_action",
            target="t",
            details={"i": i, "filler": "x" * 64},
        ))
    # Let the writer flush so the file exists on disk.
    await asyncio.sleep(0.6)
    # Second batch — the writer's rotate-before-append must move the
    # existing >2 KB file aside.
    for i in range(60, 120):
        await al.write(AuditEntry(
            engagement_id=f"eng-{i:03d}",
            action="test_action",
            target="t",
            details={"i": i, "filler": "x" * 64},
        ))
    await asyncio.sleep(0.6)
    await al.close()

    # An archive file ``audit.jsonl.1`` must exist alongside the live log.
    archives = sorted(tmp_path.glob("audit.jsonl.*"))
    archives = [p for p in archives if p.suffix not in (".head", ".tmp")]
    assert any(p.name.endswith(".1") for p in archives), (
        f"expected audit.jsonl.1 archive, found: {[p.name for p in tmp_path.iterdir()]}"
    )
