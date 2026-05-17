#!/usr/bin/env python3
"""
scripts/migrate_creds_v23.py — Migrate operator credentials from
v2.2 plaintext to v2.3 Argon2id at-rest hashing.

What it does (idempotent):

* Walks the operator-controlled credential sources:
    1. ``.env`` (or the file pointed at by ``--env``) — looks for
       ``SAP_DASHBOARD_PASS=...`` and ``SAP_DASHBOARD_USERS={...}``.
    2. ``SAP_DASHBOARD_PASS`` in the current environment.
    3. ``SAP_DASHBOARD_USERS`` JSON in the current environment.

* For every plaintext password it finds, generates the Argon2id hash
  using ``core.credentials.hash_password`` (OWASP 2024 baseline).

* For ``.env``:
    - Replaces the plaintext value in place with the hash.
    - Adds a comment line above the migrated entry documenting the
      migration date and tooling version.
    - Refuses to clobber a value that already looks like an Argon2id
      hash (the migration is a one-shot).

* For ``SAP_DASHBOARD_USERS`` (env or .env): rewrites the entries to
  use ``pass_hash`` instead of ``pass``, preserving the role.

Usage::

    python -m scripts.migrate_creds_v23 [--env PATH] [--dry-run] [--backup]

Flags:
    --env PATH      Path to the dotenv file to migrate. Defaults to the
                    repository .env (looked up relative to CWD).
    --dry-run       Print what would change without writing.
    --backup        Write ``<env>.bak.<timestamp>`` before mutating.

Exit codes:
    0   migration applied (or dry-run reported actions)
    1   nothing to migrate (no plaintext found)
    2   error (file missing / malformed JSON / refusal)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from core.credentials import hash_password, looks_like_argon2id  # noqa: E402


def _utcnow_stamp() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def _migrate_dashboard_pass(env_text: str) -> tuple[str, bool, list[str]]:
    """Rewrite ``SAP_DASHBOARD_PASS=<plaintext>`` to its Argon2id hash.

    Returns ``(new_env_text, changed, notes)``.
    """
    notes: list[str] = []
    out_lines: list[str] = []
    changed = False
    for line in env_text.splitlines(keepends=False):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        if not stripped.startswith("SAP_DASHBOARD_PASS="):
            out_lines.append(line)
            continue
        value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        if not value:
            out_lines.append(line)
            continue
        if looks_like_argon2id(value):
            notes.append("SAP_DASHBOARD_PASS already Argon2id-encoded; skipping")
            out_lines.append(line)
            continue
        new_hash = hash_password(value)
        notes.append(
            f"SAP_DASHBOARD_PASS migrated from plaintext to Argon2id (m=65536,t=3,p=4) "
            f"on {_utcnow_stamp()}"
        )
        out_lines.append(f"# migrated by scripts/migrate_creds_v23.py at {_utcnow_stamp()}")
        out_lines.append(f"SAP_DASHBOARD_PASS={new_hash}")
        changed = True
    return ("\n".join(out_lines) + ("\n" if env_text.endswith("\n") else "")), changed, notes


def _migrate_dashboard_users(env_text: str) -> tuple[str, bool, list[str]]:
    """Rewrite ``SAP_DASHBOARD_USERS=<json>`` entries from ``pass`` to
    ``pass_hash``. Preserves the role field; refuses entries that already
    declare ``pass_hash``."""
    notes: list[str] = []
    out_lines: list[str] = []
    changed = False
    for line in env_text.splitlines(keepends=False):
        stripped = line.strip()
        if not stripped.startswith("SAP_DASHBOARD_USERS="):
            out_lines.append(line)
            continue
        value = stripped.split("=", 1)[1].strip().strip('"').strip("'")
        if not value:
            out_lines.append(line)
            continue
        try:
            obj = json.loads(value)
        except json.JSONDecodeError as exc:
            notes.append(f"SAP_DASHBOARD_USERS not valid JSON ({exc}); skipping")
            out_lines.append(line)
            continue
        if not isinstance(obj, dict):
            notes.append("SAP_DASHBOARD_USERS is not a JSON object; skipping")
            out_lines.append(line)
            continue
        migrated_obj: dict[str, dict] = {}
        users_changed = 0
        for u, info in obj.items():
            if not isinstance(info, dict):
                migrated_obj[u] = info
                continue
            role = info.get("role")
            if "pass_hash" in info and info["pass_hash"]:
                migrated_obj[u] = info
                continue
            plaintext = info.get("pass")
            if not plaintext:
                migrated_obj[u] = info
                continue
            migrated_obj[u] = {
                "pass_hash": hash_password(str(plaintext)),
            }
            if role:
                migrated_obj[u]["role"] = role
            users_changed += 1
        if users_changed:
            notes.append(
                f"SAP_DASHBOARD_USERS: migrated {users_changed} plaintext "
                f"entries to Argon2id"
            )
            out_lines.append(f"# migrated by scripts/migrate_creds_v23.py at {_utcnow_stamp()}")
            out_lines.append(
                f"SAP_DASHBOARD_USERS={json.dumps(migrated_obj, separators=(',', ':'))}"
            )
            changed = True
        else:
            out_lines.append(line)
    return ("\n".join(out_lines) + ("\n" if env_text.endswith("\n") else "")), changed, notes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="migrate_creds_v23",
        description="Migrate SAP-Pentest operator credentials to Argon2id at-rest hashing.",
    )
    p.add_argument(
        "--env", default=str(REPO / ".env"),
        help="Path to the dotenv file to migrate (default: ./.env)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Print the diff without writing.",
    )
    p.add_argument(
        "--backup", action="store_true",
        help="Write <env>.bak.<timestamp> before mutating.",
    )
    args = p.parse_args(argv)

    env_path = Path(args.env)
    if not env_path.is_file():
        print(f"ERROR: dotenv file not found: {env_path}", file=sys.stderr)
        return 2

    original = env_path.read_text(encoding="utf-8")

    text, changed_pass, notes_pass = _migrate_dashboard_pass(original)
    text, changed_users, notes_users = _migrate_dashboard_users(text)
    notes = notes_pass + notes_users

    for n in notes:
        print(f"  • {n}")

    if not (changed_pass or changed_users):
        print("nothing to migrate (no plaintext entries found).")
        return 1

    if args.dry_run:
        print("\n--- dry-run: file would change to ---")
        sys.stdout.write(text)
        return 0

    if args.backup:
        backup = env_path.with_suffix(f".bak.{_utcnow_stamp()}")
        shutil.copy2(env_path, backup)
        print(f"backup saved to: {backup}")

    env_path.write_text(text, encoding="utf-8")
    print(f"migration applied to: {env_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
