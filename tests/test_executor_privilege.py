"""Argument-aware sudo detection in core.executor._needs_sudo."""
from __future__ import annotations

import pytest

from core import executor as ex


def test_static_allowlist_responder():
    assert ex._needs_sudo("responder", ["-I", "eth0"]) is True


def test_static_allowlist_tcpdump():
    assert ex._needs_sudo("tcpdump", ["-i", "lo", "-c", "1"]) is True


def test_unprivileged_tool_no_args():
    assert ex._needs_sudo("whatweb", ["http://localhost"]) is False


def test_nmap_tcp_connect_no_root():
    """nmap -sT works without sudo."""
    assert ex._needs_sudo("nmap", ["-sT", "-p", "80,443", "127.0.0.1"]) is False


def test_nmap_syn_scan_needs_root():
    """nmap -sS requires raw sockets."""
    assert ex._needs_sudo("nmap", ["-sS", "-p", "22", "127.0.0.1"]) is True


def test_nmap_udp_scan_needs_root():
    assert ex._needs_sudo("nmap", ["-sU", "-p", "53", "127.0.0.1"]) is True


def test_nmap_os_detection_needs_root():
    assert ex._needs_sudo("nmap", ["-O", "127.0.0.1"]) is True


def test_nmap_traceroute_needs_root():
    assert ex._needs_sudo("nmap", ["--traceroute", "127.0.0.1"]) is True


def test_nmap_version_scan_no_root():
    assert ex._needs_sudo("nmap", ["-sV", "-p", "80", "127.0.0.1"]) is False


def test_hping3_always_needs_root():
    assert ex._needs_sudo("hping3", ["-S", "127.0.0.1"]) is True


def test_ping_default_no_root():
    assert ex._needs_sudo("ping", ["-c", "1", "127.0.0.1"]) is False


def test_ping_flood_needs_root():
    assert ex._needs_sudo("ping", ["-f", "127.0.0.1"]) is True


def test_sudo_disabled_short_circuits(monkeypatch):
    """When sudo.enabled=false in config, never escalate."""
    monkeypatch.setattr(ex, "_sudo_enabled", lambda: False)
    assert ex._needs_sudo("responder", ["-I", "eth0"]) is False
    assert ex._needs_sudo("nmap", ["-sS", "127.0.0.1"]) is False
