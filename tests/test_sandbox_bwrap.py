"""Real bwrap escape tests — gated by the ``sandbox`` pytest marker.

These tests spawn bwrap via subprocess and assert that a hostile command
running inside the profile CANNOT:

* write outside its bind_rw allowlist (filesystem escape)
* reach the public internet (network unshare for blueteam/engagement)
* acquire CAP_SYS_ADMIN / setuid (capability escape)
* mutate /proc/sys/kernel/core_pattern (kernel-tunable escape)

Requirements at runtime:
  * ``bwrap`` on PATH (apt install bubblewrap)
  * ``kernel.unprivileged_userns_clone=1`` so non-root can spawn user-ns
  * On GitHub-hosted Ubuntu runners user namespaces are usually OK but
    `--unshare-net` requires `CAP_NET_ADMIN` for the kernel; if missing,
    the bwrap call exits with status 1 and the test will skip.

Wired into the dedicated CI workflow:
  .github/workflows/ci-sandbox.yml → runs on [self-hosted, userns]
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core import sandbox

pytestmark = pytest.mark.sandbox

if not shutil.which("bwrap"):
    pytest.skip("bwrap not on PATH; skipping real sandbox escape tests", allow_module_level=True)


@pytest.fixture(autouse=True)
def _reset_caches():
    sandbox.reset_caches()
    yield
    sandbox.reset_caches()


def _run(argv: list[str], *, timeout: float = 10.0) -> subprocess.CompletedProcess:
    """Run argv with a short timeout, capturing stdout/stderr."""
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _try_userns_or_skip():
    """Quick probe: if even an empty bwrap invocation fails (no userns),
    skip the whole test module — the environment cannot run it."""
    probe = _run(["bwrap", "--unshare-user", "--ro-bind", "/usr", "/usr", "--", "true"])
    if probe.returncode != 0:
        pytest.skip(
            "bwrap could not allocate a user namespace on this host "
            f"(probe exit={probe.returncode}, stderr={probe.stderr[:160]!r}); "
            "set kernel.unprivileged_userns_clone=1 or run on the userns runner."
        )


# ── Filesystem escape ─────────────────────────────────────────────────────


def test_recon_profile_rejects_write_outside_workdir(tmp_path, monkeypatch):
    """A tool inside the recon sandbox must NOT be able to write to /etc."""
    _try_userns_or_skip()
    monkeypatch.setenv("SAP_SANDBOX", "on")
    profile = sandbox.load_profile("recon")
    # Use a tmp_path workdir so we do not pollute /tmp.
    profile = {**profile, "workdir_template": str(tmp_path / "work-{run_id}")}

    argv = sandbox._build_bwrap_argv(
        profile, ["sh", "-c", "echo HOSTILE > /etc/escape-marker; cat /etc/escape-marker"],
        run_id="escape_fs",
    )
    _run(argv)
    # Either bwrap refuses (non-zero exit because the write was blocked)
    # OR the write went to the sandbox tmpfs and the host /etc remains clean.
    # Either way, the only thing that matters is that the HOST /etc is intact.
    assert not Path("/etc/escape-marker").exists(), (
        "Sandbox escape: hostile command wrote to host /etc"
    )


def test_blueteam_profile_blocks_outbound_network(tmp_path, monkeypatch):
    """The blueteam profile uses --unshare-net; an outbound HTTP probe
    inside the sandbox must NOT reach a routable address."""
    _try_userns_or_skip()
    monkeypatch.setenv("SAP_SANDBOX", "on")
    profile = sandbox.load_profile("blueteam")
    profile = {**profile, "workdir_template": str(tmp_path / "blueteam-{run_id}")}

    # Use `getent hosts 1.1.1.1` which works without network for IP literals
    # but `nc -zv -w2 1.1.1.1 80` (or python socket) will fail without net.
    # We use python because it's guaranteed inside /usr/bin.
    code = (
        "import socket, sys\n"
        "try:\n"
        "    s = socket.socket(); s.settimeout(2); s.connect(('1.1.1.1', 80))\n"
        "    sys.exit('NET_ESCAPE')\n"
        "except OSError as e:\n"
        "    sys.exit(0)\n"
    )
    argv = sandbox._build_bwrap_argv(
        profile, ["python3", "-c", code], run_id="escape_net",
    )
    result = _run(argv)
    # Expect exit 0 (socket failed) — anything else means the network
    # escaped the sandbox.
    assert result.returncode == 0, (
        f"Sandbox escape: outbound socket succeeded inside blueteam profile.\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


def test_exploit_profile_drops_all_capabilities(tmp_path, monkeypatch):
    """A tool inside the exploit sandbox must NOT have CAP_SYS_ADMIN."""
    _try_userns_or_skip()
    monkeypatch.setenv("SAP_SANDBOX", "on")
    profile = sandbox.load_profile("exploit")
    profile = {**profile, "workdir_template": str(tmp_path / "exploit-{run_id}")}

    # /proc/self/status reports the effective caps in hex. CapEff: 0000... means
    # zero effective caps. We verify the line equals 0 for the "AmbientCaps"
    # category since user-ns + cap-drop should yield empty caps for our uid.
    cmd = ["sh", "-c", "grep -E '^CapEff:' /proc/self/status"]
    argv = sandbox._build_bwrap_argv(profile, cmd, run_id="cap_check")
    result = _run(argv)
    if result.returncode != 0:
        pytest.skip(f"bwrap invocation failed: {result.stderr[:160]!r}")
    line = result.stdout.strip()
    # Format: "CapEff:	0000000000000000"
    hex_part = line.split(":", 1)[1].strip()
    assert int(hex_part, 16) == 0, f"Sandbox capability leak: CapEff={line!r}"


def test_recon_profile_cannot_mutate_core_pattern(tmp_path, monkeypatch):
    """/proc/sys/kernel/core_pattern is a global kernel tunable; writing
    to it from a sandbox would let an attacker hijack core dumps. Must be
    read-only inside the sandbox."""
    _try_userns_or_skip()
    monkeypatch.setenv("SAP_SANDBOX", "on")
    profile = sandbox.load_profile("recon")
    profile = {**profile, "workdir_template": str(tmp_path / "core-{run_id}")}

    cmd = [
        "sh", "-c",
        "echo |MARKER| > /proc/sys/kernel/core_pattern && cat /proc/sys/kernel/core_pattern",
    ]
    argv = sandbox._build_bwrap_argv(profile, cmd, run_id="core_pattern")
    result = _run(argv)
    # We expect a non-zero exit because the write fails (RO mount or EPERM).
    assert result.returncode != 0, (
        f"Sandbox escape: write to /proc/sys/kernel/core_pattern succeeded.\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    # And the host's core_pattern is unchanged from |MARKER|.
    host_core_pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
    assert "|MARKER|" not in host_core_pattern, (
        "Sandbox escape: host kernel.core_pattern was modified"
    )


def test_engagement_profile_is_fully_isolated(tmp_path, monkeypatch):
    """engagement profile has network_policy=none AND should block both
    filesystem writes outside /work and outbound sockets."""
    _try_userns_or_skip()
    monkeypatch.setenv("SAP_SANDBOX", "on")
    profile = sandbox.load_profile("engagement")
    profile = {**profile, "workdir_template": str(tmp_path / "eng-{run_id}")}

    argv = sandbox._build_bwrap_argv(
        profile, ["sh", "-c", "touch /usr/MARK && stat /usr/MARK"],
        run_id="eng_fs",
    )
    result = _run(argv)
    assert result.returncode != 0
    assert not Path("/usr/MARK").exists()
