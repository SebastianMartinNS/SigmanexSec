"""P4.1 — systemd unit hardening lint."""
from __future__ import annotations

from pathlib import Path

import pytest

UNITS = Path(__file__).resolve().parent.parent / "deploy" / "systemd"

REQUIRED_FOR_UNPRIV = {
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "NoNewPrivileges=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "LockPersonality=yes",
    "SystemCallArchitectures=native",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "LimitCORE=0",
    "RestrictNamespaces=yes",
}

# Files that intentionally relax some directives.
EXEMPT = {
    "sap-llm.service":           {"PrivateDevices=yes"},      # GPU
    "sap-sudo-broker.service":   REQUIRED_FOR_UNPRIV,         # runs as root
}


def _content(name):
    return (UNITS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("unit", [
    "sap-llm.service",
    "sap-dashboard.service",
    "sap-sudo-broker.service",
    "sap-mcp@.service",
])
def test_unit_files_exist(unit):
    assert (UNITS / unit).exists(), unit


@pytest.mark.parametrize("unit", [
    "sap-dashboard.service",
    "sap-mcp@.service",
])
def test_unprivileged_units_have_full_hardening(unit):
    body = _content(unit)
    missing = [d for d in REQUIRED_FOR_UNPRIV if d not in body]
    assert not missing, f"{unit} missing: {missing}"


def test_dashboard_binds_loopback_only():
    body = _content("sap-dashboard.service")
    assert "IPAddressDeny=any" in body
    assert "IPAddressAllow=127.0.0.0/8" in body
    assert "--host 127.0.0.1" in body


def test_sudo_broker_unix_only():
    body = _content("sap-sudo-broker.service")
    assert "RestrictAddressFamilies=AF_UNIX" in body
    assert "IPAddressDeny=any" in body
    # Must not allow any network family beyond AF_UNIX.
    raf_lines = [line for line in body.splitlines() if line.startswith("RestrictAddressFamilies=")]
    assert raf_lines == ["RestrictAddressFamilies=AF_UNIX"], raf_lines


def test_llm_does_not_set_mdwe_yes():
    """llama.cpp + CUDA needs PROT_EXEC on JIT pages; MDWE must be off."""
    body = _content("sap-llm.service")
    assert "MemoryDenyWriteExecute=no" in body


def test_install_script_creates_sap_user():
    body = _content("install.sh")
    assert "useradd --system" in body
    assert "/var/lib/sap" in body
    assert "/etc/sap" in body
    assert "systemctl daemon-reload" in body
