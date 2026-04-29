#!/usr/bin/env python3
"""
scripts/test_sudo_pw.py — Standalone diagnostic for sudo password validation.

Runs *exactly* the same code path the broker uses (validate_with_sudo),
so it tells you whether the password you typed is accepted by the system.
Bypasses the dashboard, the browser, and the UDS broker entirely.

Usage:
    python3 scripts/test_sudo_pw.py

Press Ctrl-C to abort. The password is read with getpass (not echoed) and
zeroized after use. No password material is logged.
"""
from __future__ import annotations

import asyncio
import getpass
import sys

from core.sudo_broker import validate_with_sudo


async def _main() -> int:
    print("=== sudo password live test (broker code path) ===")
    print("This calls `sudo -k` then `sudo -S -v` with the password you type.")
    print("If the system rejects it here, it will reject it in the dashboard too.\n")
    try:
        pw = getpass.getpass("sudo password: ")
    except (KeyboardInterrupt, EOFError):
        print("\naborted.")
        return 130
    if not pw:
        print("empty password, aborting.")
        return 2
    pw_bytes = pw.encode("utf-8")
    print(f"[debug] length={len(pw_bytes)} bytes, "
          f"contains_space={any(c in (0x20, 0x09) for c in pw_bytes)}, "
          f"trailing_ws={pw != pw.rstrip()}, "
          f"leading_ws={pw != pw.lstrip()}")
    ok, diag = await validate_with_sudo(pw_bytes, timeout=15.0)
    if ok:
        print("\nRESULT: ✅ sudo accepted the password.")
        print("→ If the dashboard still says 'invalid', the problem is in the")
        print("  browser input (typo / paste mangling / browser autofill).")
        return 0
    print("\nRESULT: ❌ sudo rejected the password.")
    if diag:
        print(f"sudo says: {diag}")
    print("\nLikely causes:")
    print(" • You typed a different password than your real Unix login password.")
    print(" • Your account uses a different auth method (LDAP/SSSD/Kerberos)")
    print("   and the cached Unix password is stale.")
    print(" • Keyboard layout (e.g. é/è/à or AltGr chars) produces different bytes")
    print("   in the terminal vs the browser.")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
