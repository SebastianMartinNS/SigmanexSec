"""P4.2 — Podman rootless artefact lint."""
from __future__ import annotations

import json
from pathlib import Path

PODMAN = Path(__file__).resolve().parent.parent / "deploy" / "podman"


def _read(name):
    return (PODMAN / name).read_text(encoding="utf-8")


def test_containerfile_uses_nonroot_user():
    body = _read("Containerfile.dashboard")
    assert "USER sap:sap" in body
    assert "useradd --system" in body


def test_containerfile_pins_python():
    body = _read("Containerfile.dashboard")
    assert "FROM docker.io/python:3.13-slim" in body


def test_containerfile_prefers_hash_locked_deps():
    body = _read("Containerfile.dashboard")
    assert "--require-hashes -r requirements.lock" in body


def test_containerfile_uses_tini_init():
    body = _read("Containerfile.dashboard")
    assert 'ENTRYPOINT ["/usr/bin/tini"' in body


def test_quadlet_drops_all_caps_and_disables_new_privs():
    body = _read("sap-dashboard.container")
    assert "DropCapability=ALL" in body
    assert "NoNewPrivileges=true" in body
    assert "ReadOnly=true" in body


def test_quadlet_publishes_loopback_only():
    body = _read("sap-dashboard.container")
    assert "PublishPort=127.0.0.1:8765:8765" in body
    # No raw `:8765:8765` (would bind 0.0.0.0).
    for line in body.splitlines():
        if line.startswith("PublishPort="):
            assert "127.0.0.1" in line, line


def test_quadlet_attaches_seccomp_profile():
    body = _read("sap-dashboard.container")
    assert "SeccompProfile=/etc/sap/seccomp-dashboard.json" in body


def test_seccomp_json_is_valid_and_default_errno():
    obj = json.loads(_read("seccomp-dashboard.json"))
    assert obj["defaultAction"] == "SCMP_ACT_ERRNO"
    # An allowlist must exist with at least the basics.
    allow = [s for s in obj["syscalls"] if s["action"] == "SCMP_ACT_ALLOW"]
    flat = sum((s["names"] for s in allow), [])
    for syscall in ("read", "write", "openat", "close", "mmap", "epoll_wait"):
        assert syscall in flat, syscall


def test_network_quadlet_internal_only():
    body = _read("sap.network")
    assert "Internal=true" in body
    assert "DisableDNS=true" in body
