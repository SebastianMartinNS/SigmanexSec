"""P2.4 — process-level memory & coredump protections."""
from __future__ import annotations

import os
import resource
import subprocess
import sys
import textwrap


def test_harden_process_returns_status():
    from core.process_hardening import harden_process
    s = harden_process()
    d = s.to_dict()
    assert set(d.keys()) >= {
        "rlimit_core_zero", "pr_set_dumpable_off", "mlockall_done", "notes",
    }


def test_harden_process_disables_core_dumps():
    """Run in a subprocess so we don't squash this test runner's RLIMIT_CORE."""
    code = textwrap.dedent("""
        import json, resource, sys
        from core.process_hardening import harden_process
        before = resource.getrlimit(resource.RLIMIT_CORE)
        s = harden_process()
        after = resource.getrlimit(resource.RLIMIT_CORE)
        out = {"before": before, "after": after, "status": s.to_dict()}
        sys.stdout.write(json.dumps(out))
    """)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, check=True,
    )
    import json as _json
    out = _json.loads(proc.stdout)
    assert out["after"] == [0, 0]
    assert out["status"]["rlimit_core_zero"] is True


def test_mlockall_off_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SAP_MLOCK_ALL", raising=False)
    from core.process_hardening import harden_process
    s = harden_process()
    assert s.mlockall_done is False
