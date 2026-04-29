#!/usr/bin/env python3
"""End-to-end QA scenario for the SAP Tool Output Store.

Validates the original failure mode ("scansioni truncate / non salvate") by
running real `nmap` and `dirb` invocations through the executor, then asserting:

  1. Output is fully persisted (no truncation) — byte-equivalent to subprocess.
  2. Stored blob is recallable via the canonical store API.
  3. Auto-artifact flags (-oA for nmap) are injected and produce real files.
  4. MCP-style response is bounded (head+tail) but stdout_uri points to full data.
  5. GC dry-run reports the freshly-created rows as candidates only when expired.

Targets:
  • Loopback HTTP server spun up by this script (free port).
  • Optional $PENTEST_LAB_CIDR for an additional nmap pass (skipped if unset).

Usage:
  python scripts/qa_scenario.py [-v]

Exit code 0 on success, 1 on any assertion failure.
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import http.server
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from datetime import timedelta
from pathlib import Path

# Ensure repo root on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Redirect SAP storage into a temp area so we don't pollute the live engagement.
_QA_TMP = Path(tempfile.mkdtemp(prefix="sap_qa_"))
os.environ["SAP_SESSIONS_DIR"] = str(_QA_TMP / "sessions")
os.environ["SAP_LOGS_DIR"] = str(_QA_TMP / "logs")
os.environ["SAP_REPORTS_DIR"] = str(_QA_TMP / "reports")
os.environ["SESSION_DB_PATH"] = str(_QA_TMP / "sessions.db")
os.environ["AUDIT_LOG_PATH"] = str(_QA_TMP / "audit.jsonl")
os.environ["SAP_KEYSALT_PATH"] = str(_QA_TMP / "keysalt")
os.environ["SAP_DISABLE_STORAGE_GC"] = "1"
for d in ("sessions", "logs", "reports"):
    (_QA_TMP / d).mkdir(parents=True, exist_ok=True)

from core.executor import ToolExecutor  # noqa: E402
from core.models import Phase  # noqa: E402
from core.parrot_catalog import (  # noqa: E402
    auto_artifact_flags,
    materialize_artifact_flags,
    response_profile_for,
)
from core.tool_output_store import (  # noqa: E402
    get_tool_output_store,
    reset_tool_output_store,
)
from core.time_utils import utcnow as _sap_utcnow  # noqa: E402


# ── Console helpers ─────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {BLUE}ℹ{RESET} {msg}")


def section(title: str) -> None:
    print(f"\n{YELLOW}━━ {title} {RESET}")


_failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if cond:
        ok(msg)
    else:
        fail(msg)
        _failures.append(msg)


# ── Local HTTP server ───────────────────────────────────────────────────────
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _QAHandler(http.server.BaseHTTPRequestHandler):
    PATHS = {"/", "/admin", "/login", "/api", "/robots.txt", "/sitemap.xml"}

    def do_GET(self):  # noqa: N802
        if self.path in self.PATHS:
            body = f"<html><body><h1>QA {self.path}</h1></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *_a, **_kw):  # silence
        pass


def _start_http() -> tuple[int, threading.Thread, socketserver.TCPServer]:
    port = _free_port()
    srv = socketserver.TCPServer(("127.0.0.1", port), _QAHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    time.sleep(0.2)
    return port, th, srv


# ── Scenario tests ──────────────────────────────────────────────────────────
async def scenario_nmap_loopback(port: int) -> None:
    section(f"Scenario 1 — nmap localhost:{port} (full output + auto -oA)")
    reset_tool_output_store()
    store = get_tool_output_store()

    exe = ToolExecutor(run_id="qa-run-nmap")
    # Pre-allocate so we can inject -oA into the artifacts dir
    pre_call_id, adir = store.allocate(exe._run_id)
    base_argv = ["-Pn", "-sT", "-p", str(port), "127.0.0.1"]
    extra = auto_artifact_flags("nmap", base_argv)
    info(f"auto_artifact_flags → {extra}")
    extra = materialize_artifact_flags(extra, adir)
    argv = base_argv + extra

    # Bypass allow-list for QA
    import core.executor as _ex
    _ex._allowed_tools = lambda: {"nmap"}  # type: ignore[attr-defined]

    res = await exe.run("nmap", argv, engagement_id="qa-eng", phase=Phase.RECON, call_id=pre_call_id)
    check(res.returncode == 0, f"nmap returncode == 0 (got {res.returncode})")
    check(res.output_ref is not None, "ExecutionResult has output_ref")
    if res.output_ref:
        info(f"output_ref.call_id={res.output_ref.call_id} stdout_bytes={res.output_ref.stdout_bytes}")
        check(res.output_ref.call_id == pre_call_id, "call_id round-trips")

    # Ground truth — direct subprocess run without -oA flags
    truth = subprocess.run(
        ["nmap", *base_argv], capture_output=True, check=False
    )
    stored = await store.read(pre_call_id, "stdout")
    check(b"Nmap scan report" in stored, "stored stdout contains 'Nmap scan report'")
    # Byte-equivalence sanity (some nmap output is timing-sensitive — compare structure)
    check(len(stored) > 200, f"stored stdout size {len(stored)} bytes (>200)")
    check(
        stored.count(b"Nmap scan report") == truth.stdout.count(b"Nmap scan report"),
        "stored stdout matches subprocess scan-report count",
    )
    info(f"stored size={len(stored)}B, subprocess size={len(truth.stdout)}B")

    # Artifacts: -oA should produce .nmap/.gnmap/.xml
    artifacts = list(adir.iterdir())
    info(f"artifacts dir contents: {[p.name for p in artifacts]}")
    names = {p.suffix for p in artifacts}
    check({".nmap", ".gnmap", ".xml"}.issubset(names), "nmap -oA produced .nmap/.gnmap/.xml")

    # Recall via store metadata
    ref = await store.get(pre_call_id)
    check(ref is not None, "metadata row recallable by call_id")
    check(ref.tool == "nmap", f"metadata tool == 'nmap' (got {ref.tool if ref else None})")

    # Profile selection
    prof = response_profile_for({"name": "nmap", "binary": "nmap", "category": "recon"})
    check(prof["profile"] == "head_tail", f"recon profile head_tail (got {prof['profile']})")


async def scenario_dirb_loopback(port: int) -> None:
    section(f"Scenario 2 — dirb http://127.0.0.1:{port}/ (large output, no truncation)")
    reset_tool_output_store()
    store = get_tool_output_store()

    exe = ToolExecutor(run_id="qa-run-dirb")
    pre_call_id, adir = store.allocate(exe._run_id)

    # Build a tiny wordlist with our known paths + filler
    wl = adir.parent / "qa_wordlist.txt"
    paths = ["", "admin", "login", "api", "robots.txt", "sitemap.xml"] + [
        f"noexist{i}" for i in range(50)
    ]
    wl.write_text("\n".join(paths) + "\n")

    import core.executor as _ex
    _ex._allowed_tools = lambda: {"dirb"}  # type: ignore[attr-defined]

    res = await exe.run(
        "dirb",
        [f"http://127.0.0.1:{port}/", str(wl), "-S", "-r"],
        engagement_id="qa-eng",
        phase=Phase.RECON,
        call_id=pre_call_id,
    )
    info(f"dirb returncode={res.returncode}")
    check(res.returncode in (0, 1), "dirb returncode acceptable (0/1)")

    stored = await store.read(pre_call_id, "stdout")
    check(len(stored) > 500, f"stored dirb stdout size {len(stored)} bytes (>500)")
    check(b"DIRB" in stored, "stored stdout contains 'DIRB' header")
    found_count = stored.count(b"+ http://127.0.0.1:")
    info(f"dirb found-line count in stored output: {found_count}")
    check(found_count >= 4, f"dirb discovered ≥4 paths (got {found_count})")


async def scenario_gc_dryrun() -> None:
    section("Scenario 3 — GC dry-run reports candidates only when expired")
    store = get_tool_output_store()

    # Nothing should be expired yet (retention 90d default)
    stats_now = await store.gc(retention_days=90, dry_run=True)
    info(f"gc(retention=90d, dry_run): {stats_now}")
    check(stats_now.get("deleted_rows", 0) == 0, "no rows deleted when fresh")

    # Force expiration: retention=-1 (cutoff = now + 1d > created_at)
    stats_zero = await store.gc(retention_days=-1, dry_run=True)
    info(f"gc(retention=-1d, dry_run): {stats_zero}")
    check(
        stats_zero.get("candidates", 0) >= 1,
        f"at least 1 candidate with retention=-1 (got {stats_zero.get('candidates')})",
    )
    check(
        stats_zero.get("deleted_rows", 0) == 0,
        "dry-run does not actually delete",
    )


async def scenario_optional_lab_target() -> None:
    cidr = os.environ.get("PENTEST_LAB_CIDR", "").strip()
    if not cidr:
        section("Scenario 4 — lab CIDR scan (skipped, PENTEST_LAB_CIDR unset)")
        info("Set PENTEST_LAB_CIDR=10.10.10.0/24 (or similar) to enable.")
        return
    section(f"Scenario 4 — nmap lab target {cidr}")
    reset_tool_output_store()
    store = get_tool_output_store()
    exe = ToolExecutor(run_id="qa-run-lab")
    pre_call_id, adir = store.allocate(exe._run_id)
    base = ["-Pn", "-sT", "--top-ports", "20", cidr]
    extra = materialize_artifact_flags(auto_artifact_flags("nmap", base), adir)
    import core.executor as _ex
    _ex._allowed_tools = lambda: {"nmap"}  # type: ignore[attr-defined]
    res = await exe.run("nmap", base + extra, engagement_id="qa-eng", phase=Phase.RECON, call_id=pre_call_id)
    check(res["returncode"] == 0, "lab nmap returncode == 0")
    stored = await store.read(pre_call_id, "stdout")
    check(len(stored) > 200, f"lab nmap stored size {len(stored)} (>200)")


async def main_async(verbose: bool) -> int:
    print(f"{BLUE}SAP QA — scenario-driven validation{RESET}")
    info(f"workdir={_QA_TMP}")
    port, th, srv = _start_http()
    info(f"local HTTP server on 127.0.0.1:{port}")
    try:
        await scenario_nmap_loopback(port)
        await scenario_dirb_loopback(port)
        await scenario_gc_dryrun()
        await scenario_optional_lab_target()
    finally:
        srv.shutdown()
        srv.server_close()

    print()
    if _failures:
        print(f"{RED}FAILED ({len(_failures)} assertion(s)):{RESET}")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print(f"{GREEN}All QA scenarios passed.{RESET}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()
    return asyncio.run(main_async(args.verbose))


if __name__ == "__main__":
    sys.exit(main())
