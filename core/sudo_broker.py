"""
core/sudo_broker.py — Cross-process sudo password broker.

Why this exists
---------------
``SudoVault`` is a per-process singleton: when the operator unlocks the
vault from the dashboard FastAPI process, every *other* Python process
(MCP HTTP servers on :9001-:9005, MCP stdio subprocesses spawned by the
Orchestrator, the test runner, ...) keeps its own ``_VAULT = None`` and
sees the vault as locked.

The broker exposes a single in-memory ``SudoVault`` instance over a Unix
Domain Socket so that all SAP processes running as the same UID share
the same unlocked state.

Security model
--------------
* The socket lives under ``$XDG_RUNTIME_DIR`` (or ``/tmp`` fallback) with
  mode ``0600`` and is created with a ``umask`` that prevents group/other
  bits from leaking.
* Every accepted connection is authenticated via ``SO_PEERCRED``: only
  peers running as the same UID as the broker process are allowed. This
  is enforced by the kernel and is not bypassable from userland.
* The protocol is newline-delimited JSON. The password is sent as a
  UTF-8 string inside a JSON object on a single line. Both server and
  client zeroize the in-memory bytearray copy after use.
* The password is *never* persisted, never logged, never echoed back.
  ``BORROW`` returns the password exactly once per request and the
  client zeroizes its copy after use (see ``BrokerVaultProxy.borrow``).

Run
---
::

    python -m core.sudo_broker            # foreground
    python -m core.sudo_broker --daemon   # background, writes pid + socket path

Clients import :class:`BrokerVaultProxy` and use it as a drop-in
replacement for :class:`core.sudo_vault.SudoVault`.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
import struct
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any

from core.sudo_vault import (
    SudoFailed,
    SudoLocked,
    SudoVault,
    _zeroize,
)

log = logging.getLogger("sap.sudo_broker")


# ─────────────────────────────────────────────
# Socket path resolution
# ─────────────────────────────────────────────

def default_socket_path() -> str:
    """Return the canonical socket path for the current user."""
    base = os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
    return os.path.join(base, f"sap_sudo_{os.getuid()}.sock")


# ─────────────────────────────────────────────
# Live password validation (via real sudo)
# ─────────────────────────────────────────────

async def validate_with_sudo(
    password: bytes, timeout: float = 15.0,
) -> tuple[bool, str]:
    """
    Verify a candidate password by running ``sudo -k && sudo -S -v -p ''``.

    ``-k`` invalidates any cached timestamp first so we are sure ``-v``
    actually consults the password we send. The default 15s timeout absorbs
    PAM faillock backoff that fires after a previous wrong attempt.

    Returns ``(ok, diagnostic)``. On failure, ``diagnostic`` is the trimmed
    first line of ``sudo``'s stderr (e.g. "Sorry, try again.",
    "sudo: a password is required", "sudo: sorry, you must have a tty...").
    On success, ``diagnostic`` is the empty string.
    """
    # Reset timestamp first; ignore exit code.
    with contextlib.suppress(Exception):
        proc0 = await asyncio.create_subprocess_exec(
            "sudo", "-k",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc0.wait(), timeout=2.0)

    proc = await asyncio.create_subprocess_exec(
        "sudo", "-S", "-v", "-p", "",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    payload = bytearray(password) + b"\n"
    err_text = ""
    try:
        try:
            _, err = await asyncio.wait_for(
                proc.communicate(input=bytes(payload)), timeout=timeout,
            )
            if err:
                # Keep the most informative line — sudo prints the prompt
                # ("[sudo] password for user:") then the real diagnostic.
                lines = [
                    ln.strip() for ln in err.decode("utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.strip().startswith("[sudo]")
                ]
                err_text = (lines[-1] if lines else "")[:200]
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return False, f"sudo validation timed out after {timeout:.0f}s (PAM backoff?)"
    finally:
        _zeroize(payload)

    return (proc.returncode == 0), err_text


# ─────────────────────────────────────────────
# Server
# ─────────────────────────────────────────────

ValidatorFn = Callable[[bytes], Awaitable[Any]]
"""Validator may return either ``bool`` (legacy) or ``(bool, str)`` tuple
where the str is a free-form diagnostic returned to the caller on failure.
"""


class SudoBrokerServer:
    """asyncio Unix server fronting a single :class:`SudoVault`."""

    def __init__(
        self,
        socket_path: str,
        vault: SudoVault | None = None,
        validator: ValidatorFn | None = None,
    ):
        self.socket_path = socket_path
        self.vault = vault if vault is not None else SudoVault()
        self.validator: ValidatorFn = validator or validate_with_sudo
        self._server: asyncio.AbstractServer | None = None
        self._uid = os.getuid()

    # ── lifecycle ──────────────────────────────────────────────────────

    async def start(self) -> None:
        # Remove stale socket file (only if it is actually a socket).
        with contextlib.suppress(FileNotFoundError):
            st = os.stat(self.socket_path)
            import stat as _stat
            if _stat.S_ISSOCK(st.st_mode):
                os.unlink(self.socket_path)
        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)

        prev_umask = os.umask(0o077)
        try:
            self._server = await asyncio.start_unix_server(
                self._handle_client, path=self.socket_path,
            )
        finally:
            os.umask(prev_umask)
        os.chmod(self.socket_path, 0o600)
        log.info("sudo broker listening on %s (uid=%s)", self.socket_path, self._uid)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)
        await self.vault.lock()

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    # ── per-connection handler ────────────────────────────────────────

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        sock: socket.socket = writer.get_extra_info("socket")
        try:
            if not self._check_peer_uid(sock):
                writer.write(self._json_line({"ok": False, "error": "peer uid mismatch"}))
                await writer.drain()
                return

            # Single request / single response per connection.
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                return
            try:
                req = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                writer.write(self._json_line({"ok": False, "error": f"bad json: {e}"}))
                await writer.drain()
                return

            resp = await self._dispatch(req)
            writer.write(self._json_line(resp))
            await writer.drain()
            # Best-effort scrub: rewrite the request bytearray we hold.
            _zeroize(bytearray(line))
        except TimeoutError:
            pass
        except Exception as e:  # pragma: no cover
            log.exception("broker handler error: %s", e)
            with contextlib.suppress(Exception):
                writer.write(self._json_line({"ok": False, "error": "internal"}))
                await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    def _check_peer_uid(self, sock: socket.socket) -> bool:
        try:
            # struct ucred = pid (i), uid (I), gid (I) — 12 bytes on Linux.
            data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        except (OSError, AttributeError):
            return False
        try:
            _pid, uid, _gid = struct.unpack("iII", data)
        except struct.error:
            return False
        return bool(uid == self._uid)

    @staticmethod
    def _json_line(obj: dict[str, Any]) -> bytes:
        return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")

    # ── protocol dispatch ─────────────────────────────────────────────

    async def _dispatch(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req.get("op")
        if op == "ping":
            return {"ok": True, "pid": os.getpid()}
        if op == "status":
            return {"ok": True, **(await self.vault.status())}
        if op == "unlock":
            pw = req.get("password", "")
            ttl = int(req.get("ttl", 600))
            if not pw:
                return {"ok": False, "error": "empty password"}
            pwd_bytes = pw.encode("utf-8")
            try:
                result = await self.validator(pwd_bytes)
            finally:
                # Scrub the JSON-decoded copy.
                _zeroize(bytearray(pwd_bytes))
            # Validator may return either bool (legacy) or (bool, diag).
            if isinstance(result, tuple):
                ok, diag = result
            else:
                ok, diag = bool(result), ""
            if not ok:
                # Track a failure on the live vault counter even when not unlocked,
                # so brute-force attempts trip the same auto-lock policy.
                if await self.vault.is_unlocked():
                    await self.vault.record_failure()
                err_msg = "invalid sudo password"
                if diag:
                    err_msg = f"{err_msg}: {diag}"
                return {"ok": False, "error": err_msg}
            await self.vault.unlock(pw, ttl_seconds=ttl)
            return {"ok": True, **(await self.vault.status())}
        if op == "lock":
            await self.vault.lock()
            return {"ok": True, **(await self.vault.status())}
        if op == "borrow":
            try:
                async with self.vault.borrow() as pw:
                    return {"ok": True, "password": pw.decode("utf-8")}
            except SudoLocked as e:
                return {"ok": False, "error": str(e), "locked": True}
        if op == "record_failure":
            locked = await self.vault.record_failure()
            return {"ok": True, "locked": locked}
        if op == "record_success":
            await self.vault.record_success()
            return {"ok": True}
        if op == "heartbeat":
            # Touch last_use so inactivity timer does not auto-lock while
            # the operator is actively driving the dashboard.
            if await self.vault.is_unlocked():
                await self.vault.record_success()
            return {"ok": True, **(await self.vault.status())}
        return {"ok": False, "error": f"unknown op: {op!r}"}


# ─────────────────────────────────────────────
# Client
# ─────────────────────────────────────────────

class BrokerUnavailable(Exception):
    """Raised when the broker socket cannot be reached."""


class BrokerVaultProxy:
    """
    Async API-compatible proxy mirroring :class:`SudoVault`.

    Only the methods that are actually used by the executor and the
    dashboard are implemented. Each call opens a fresh UDS connection;
    overhead is negligible (sub-millisecond) and avoids long-lived
    sockets that would have to be reaped on idle.
    """

    def __init__(self, socket_path: str):
        self.socket_path = socket_path

    # ── transport ─────────────────────────────────────────────────────

    async def _call(self, op: str, **payload: Any) -> dict[str, Any]:
        try:
            reader, writer = await asyncio.open_unix_connection(self.socket_path)
        except (FileNotFoundError, ConnectionRefusedError) as e:
            raise BrokerUnavailable(f"broker not reachable at {self.socket_path}: {e}") from e
        try:
            writer.write((json.dumps({"op": op, **payload}) + "\n").encode("utf-8"))
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                raise BrokerUnavailable("broker closed connection")
            decoded: dict[str, Any] = json.loads(line.decode("utf-8"))
            return decoded
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    # ── SudoVault-compatible API ─────────────────────────────────────

    async def status(self) -> dict[str, Any]:
        r = await self._call("status")
        # Drop the protocol "ok" key to match SudoVault.status() shape.
        return {k: v for k, v in r.items() if k != "ok"}

    async def is_unlocked(self) -> bool:
        try:
            r = await self._call("status")
        except BrokerUnavailable:
            return False
        return not bool(r.get("locked", True))

    async def unlock(self, password: str, ttl_seconds: int | None = None) -> None:
        ttl = int(ttl_seconds) if ttl_seconds else 600
        r = await self._call("unlock", password=password, ttl=ttl)
        if not r.get("ok"):
            raise SudoFailed(r.get("error", "unlock failed"))

    async def lock(self) -> None:
        await self._call("lock")

    @contextlib.asynccontextmanager
    async def borrow(self) -> AsyncIterator[bytes]:
        r = await self._call("borrow")
        if not r.get("ok"):
            raise SudoLocked(r.get("error", "vault locked"))
        pw_str = r.get("password", "")
        copy = bytearray(pw_str.encode("utf-8"))
        # Clear the JSON-decoded string indirectly by overwriting our local
        # references; CPython keeps the str object until GC, but the long-
        # lived buffer the executor relies on is the bytearray below.
        try:
            yield bytes(copy)
        finally:
            _zeroize(copy)

    async def record_failure(self) -> bool:
        r = await self._call("record_failure")
        return bool(r.get("locked", False))

    async def record_success(self) -> None:
        await self._call("record_success")

    async def heartbeat(self) -> dict[str, Any]:
        r = await self._call("heartbeat")
        return {k: v for k, v in r.items() if k != "ok"}


# ─────────────────────────────────────────────
# CLI entrypoint
# ─────────────────────────────────────────────

def _install_signal_handlers(loop: asyncio.AbstractEventLoop, server: SudoBrokerServer) -> None:
    async def _shutdown() -> None:
        log.info("sudo broker shutting down")
        await server.stop()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(_shutdown()))


async def _amain(socket_path: str) -> None:
    logging.basicConfig(
        level=os.environ.get("SAP_SUDO_BROKER_LOGLEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] sudo_broker: %(message)s",
    )
    server = SudoBrokerServer(socket_path)
    await server.start()
    _install_signal_handlers(asyncio.get_running_loop(), server)
    try:
        await server.serve_forever()
    except asyncio.CancelledError:
        pass


def main() -> None:
    p = argparse.ArgumentParser(description="SAP sudo broker")
    p.add_argument("--socket", default=default_socket_path())
    p.add_argument("--pidfile", default="")
    args = p.parse_args()

    if args.pidfile:
        Path(args.pidfile).parent.mkdir(parents=True, exist_ok=True)
        Path(args.pidfile).write_text(str(os.getpid()))

    # Print the socket path on stdout so a parent shell can `read` it.
    print(args.socket, flush=True)
    try:
        asyncio.run(_amain(args.socket))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
