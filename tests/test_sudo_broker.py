"""
tests/test_sudo_broker.py — Coverage for the cross-process sudo broker.

We never invoke real ``sudo`` in tests: the validator is monkey-patched
with a deterministic comparator so the suite runs as an unprivileged
user inside CI containers.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from core.sudo_broker import (
    BrokerUnavailable, BrokerVaultProxy, SudoBrokerServer,
)
from core.sudo_vault import SudoFailed, SudoLocked, SudoVault


pytestmark = pytest.mark.asyncio


# ── helpers ──────────────────────────────────────────────────────────────

async def _spawn_broker(tmp_path, *, secret="hunter2", ttl=2, inactivity=2):
    sock = os.path.join(tmp_path, "sap_sudo_test.sock")
    vault = SudoVault(
        default_ttl_seconds=ttl,
        max_ttl_seconds=ttl,
        max_failures_before_lock=3,
        inactivity_lock_seconds=inactivity,
    )

    async def fake_validator(pw: bytes) -> bool:
        return pw == secret.encode("utf-8")

    server = SudoBrokerServer(sock, vault=vault, validator=fake_validator)
    await server.start()
    return server, sock


# ── tests ────────────────────────────────────────────────────────────────

async def test_unlock_borrow_lock_roundtrip(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        assert await proxy.is_unlocked() is False

        await proxy.unlock("hunter2", ttl_seconds=5)
        assert await proxy.is_unlocked() is True

        async with proxy.borrow() as pw:
            assert pw == b"hunter2"

        await proxy.lock()
        assert await proxy.is_unlocked() is False
    finally:
        await server.stop()


async def test_wrong_password_raises_sudo_failed(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        with pytest.raises(SudoFailed):
            await proxy.unlock("wrong", ttl_seconds=5)
        assert await proxy.is_unlocked() is False
    finally:
        await server.stop()


async def test_borrow_when_locked_raises(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        with pytest.raises(SudoLocked):
            async with proxy.borrow():
                pass
    finally:
        await server.stop()


async def test_ttl_expiry(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path), ttl=1, inactivity=10)
    try:
        proxy = BrokerVaultProxy(sock)
        await proxy.unlock("hunter2", ttl_seconds=1)
        assert await proxy.is_unlocked() is True
        await asyncio.sleep(1.2)
        assert await proxy.is_unlocked() is False
    finally:
        await server.stop()


async def test_heartbeat_resets_inactivity(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path), ttl=10, inactivity=2)
    try:
        proxy = BrokerVaultProxy(sock)
        await proxy.unlock("hunter2", ttl_seconds=10)
        # Sleep just under the inactivity bound and beat.
        await asyncio.sleep(1.2)
        await proxy.heartbeat()
        await asyncio.sleep(1.2)
        # Still unlocked because heartbeat reset last_use.
        assert await proxy.is_unlocked() is True
    finally:
        await server.stop()


async def test_record_failure_locks_after_threshold(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        await proxy.unlock("hunter2", ttl_seconds=10)
        assert await proxy.record_failure() is False
        assert await proxy.record_failure() is False
        assert await proxy.record_failure() is True
        assert await proxy.is_unlocked() is False
    finally:
        await server.stop()


async def test_unavailable_socket_raises(tmp_path):
    proxy = BrokerVaultProxy(os.path.join(str(tmp_path), "nope.sock"))
    with pytest.raises(BrokerUnavailable):
        await proxy.status()


async def test_concurrent_borrows(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        await proxy.unlock("hunter2", ttl_seconds=10)

        async def one():
            async with proxy.borrow() as pw:
                assert pw == b"hunter2"

        await asyncio.gather(*(one() for _ in range(10)))
    finally:
        await server.stop()


async def test_status_shape(tmp_path):
    server, sock = await _spawn_broker(str(tmp_path))
    try:
        proxy = BrokerVaultProxy(sock)
        st = await proxy.status()
        assert st["locked"] is True
        assert "ttl_remaining_seconds" in st
        await proxy.unlock("hunter2", ttl_seconds=5)
        st = await proxy.status()
        assert st["locked"] is False
        assert st["ttl_remaining_seconds"] > 0
    finally:
        await server.stop()
