"""
core/credentials.py — Argon2id at-rest hashing for operator credentials.

Wraps ``argon2-cffi`` with the OWASP 2024 baseline parameters and a tiny
public surface so every credential-handling site in the project goes
through the same primitive. Replaces the historical
``secrets.compare_digest(plaintext_a, plaintext_b)`` checks in
``sap_dashboard/backend/{security,rbac,deps}.py`` — those compared a
plaintext password held in memory against another plaintext password
supplied by the client, which left the operator credential exposed to
any process dump or core file.

OWASP 2024 parameters (server-side, latency-bounded):

* ``type``      = Argon2id (the side-channel-resistant variant)
* ``memory_cost`` = 65 536 KiB (64 MiB)
* ``time_cost`` = 3 iterations
* ``parallelism`` = 4 threads
* ``hash_len`` = 32 bytes
* ``salt_len``  = 16 bytes

These are deliberately on the higher end of OWASP's range so a stolen
hash database is expensive to crack offline.

Public API:

    h = hash_password("hunter2")              # str, "$argon2id$..."
    ok = verify_password("hunter2", h)        # bool
    needs = needs_rehash(h)                   # True if params drifted

``verify_password`` always swallows malformed hashes and returns False;
it never raises on user input. Use ``needs_rehash`` after a successful
verify to silently upgrade old hashes on next login.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# OWASP 2024 recommended baseline for server-side Argon2id (interactive
# login latency budget ~50–100 ms on a modern x86_64 core).
_TIME_COST = 3
_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
_PARALLELISM = 4
_HASH_LEN = 32
_SALT_LEN = 16

_HASHER = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST_KIB,
    parallelism=_PARALLELISM,
    hash_len=_HASH_LEN,
    salt_len=_SALT_LEN,
)


def hash_password(plain: str) -> str:
    """Return an Argon2id encoded hash for *plain*. Raises ValueError if
    *plain* is empty (an empty password must never reach the hasher)."""
    if not isinstance(plain, str) or not plain:
        raise ValueError("hash_password: refusing empty password")
    return _HASHER.hash(plain)


def verify_password(plain: str, stored: str | None) -> bool:
    """Return True if *plain* matches the encoded Argon2id *stored* hash.

    Safe for arbitrary user input: every failure mode (missing hash,
    malformed hash, mismatched verify) collapses to a uniform False
    return so callers cannot leak information through exception type.

    For backwards-compat with the v2.2 plaintext-only ``SAP_DASHBOARD_USERS``
    format, callers should NOT pass plaintext as *stored*. The dashboard's
    migration shim handles that fall-through path explicitly via
    ``looks_like_argon2id`` so the deprecation event is logged once.
    """
    if not stored or not plain:
        return False
    if not looks_like_argon2id(stored):
        return False
    try:
        _HASHER.verify(stored, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return True


def needs_rehash(stored: str) -> bool:
    """Return True if *stored* uses parameters weaker than the current
    baseline (e.g. an older hash created with smaller memory_cost). The
    caller should re-hash with ``hash_password(plain)`` and persist the
    new value on the next successful login."""
    if not looks_like_argon2id(stored):
        return True
    try:
        return bool(_HASHER.check_needs_rehash(stored))
    except InvalidHashError:
        return True


def looks_like_argon2id(value: str | None) -> bool:
    """Cheap shape check so the verify path can refuse plaintext-shaped
    inputs before the argon2-cffi machinery raises. Does NOT validate
    the cryptographic integrity of the hash — that is verify_password's job."""
    if not value or not isinstance(value, str):
        return False
    return value.startswith("$argon2id$") or value.startswith("$argon2i$") or value.startswith("$argon2d$")


def generate_random_password(length: int = 24) -> str:
    """Generate a URL-safe random password suitable for first-boot bootstrap
    or one-shot service-account credentials. ``secrets.token_urlsafe(N)``
    returns roughly 1.3·N characters, so 24 bytes ≈ 32-char string."""
    if length < 16:
        raise ValueError("generate_random_password: refusing length < 16 bytes")
    return secrets.token_urlsafe(length)
