"""
core/session_store.py — Async SQLite persistence layer.

Stores engagements, hosts, services, findings, and credentials.
Credentials are stored AES-256-GCM encrypted at rest.
All reads/writes are async (aiosqlite).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

import aiosqlite
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.models import (
    Credential,
    Engagement,
    EngagementStatus,
    Finding,
    Host,
    Phase,
    Service,
)
from core.paths import is_dev_mode, keysalt_path
from core.time_utils import utcnow as _sap_utcnow

_log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Credential encryption helpers
# ─────────────────────────────────────────────

_LEGACY_DEV_KEY = b"SAP_DEV_KEY_CHANGE_ME_IN_PROD!!"
_PBKDF2_ITERATIONS = 480_000  # OWASP 2023 baseline for SHA-256
_KEY_CACHE: bytes | None = None
# Guards concurrent first-use of ``_derive_key``; without it, two threads
# (or a sync + async caller) could both run the expensive PBKDF2 stretch
# and then race on assigning ``_KEY_CACHE``. Using ``threading.Lock``
# rather than ``asyncio.Lock`` because ``_derive_key`` is sync and may be
# invoked from arbitrary threads (e.g. the audit GC worker).
import threading as _threading

_KEY_CACHE_LOCK = _threading.Lock()


def _load_or_create_salt() -> bytes:
    path = keysalt_path()
    if path.exists():
        data = path.read_bytes()
        if len(data) >= 16:
            return data[:32]
    salt = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(salt)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return salt


def _derive_key() -> bytes:
    """Derive a 32-byte AES key.

    Order of resolution:
      1. ``CREDENTIAL_ENCRYPTION_KEY`` (raw, hex or base64-ish) — used as-is,
         padded/truncated to 32 bytes. Useful for KMS-injected material.
      2. ``CREDENTIAL_ENCRYPTION_PASSPHRASE`` — stretched with PBKDF2-HMAC-SHA256
         using a salt persisted in ``sessions/.keysalt`` (auto-generated, 0600).
      3. In ``SAP_DEV_MODE`` only: insecure constant fallback (warns loudly).

    Otherwise the platform refuses to start (fail-fast).
    """
    global _KEY_CACHE
    if _KEY_CACHE is not None:
        return _KEY_CACHE
    with _KEY_CACHE_LOCK:
        # Double-checked: another thread may have populated the cache while
        # we were waiting on the lock. Avoid running PBKDF2 twice.
        if _KEY_CACHE is not None:
            return _KEY_CACHE

        raw = os.environ.get("CREDENTIAL_ENCRYPTION_KEY", "").strip()
        if raw:
            key = raw.encode()[:32].ljust(32, b"\x00")
            _KEY_CACHE = key
            return key

        passphrase = os.environ.get("CREDENTIAL_ENCRYPTION_PASSPHRASE", "").strip()
        if passphrase:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=_load_or_create_salt(),
                iterations=_PBKDF2_ITERATIONS,
            )
            key = kdf.derive(passphrase.encode())
            _KEY_CACHE = key
            return key

        if is_dev_mode():
            _log.warning(
                "SAP_DEV_MODE active: using insecure built-in encryption key. "
                "DO NOT use this configuration outside of local development."
            )
            _KEY_CACHE = _LEGACY_DEV_KEY
            return _LEGACY_DEV_KEY

        msg = (
            "Credential encryption is not configured. Set "
            "CREDENTIAL_ENCRYPTION_PASSPHRASE (recommended) or "
            "CREDENTIAL_ENCRYPTION_KEY in the environment, or export "
            "SAP_DEV_MODE=1 for local-lab use only."
        )
        print(f"[FATAL] {msg}", file=sys.stderr, flush=True)
        raise RuntimeError(msg)


def _encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    aesgcm = AESGCM(_derive_key())
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return (nonce + ct).hex()


def _decrypt(hex_data: str) -> str:
    if not hex_data:
        return ""
    try:
        raw = bytes.fromhex(hex_data)
        nonce, ct = raw[:12], raw[12:]
    except ValueError:
        return "[DECRYPTION_FAILED]"
    # Try the active key first; fall back to the legacy dev key so existing
    # databases stay readable during migration. Re-encrypt-on-write happens
    # naturally when callers update the credential record.
    for key in (_derive_key(), _LEGACY_DEV_KEY):
        try:
            return AESGCM(key).decrypt(nonce, ct, None).decode()
        except Exception:
            continue
    return "[DECRYPTION_FAILED]"


# ─────────────────────────────────────────────
# SessionStore
# ─────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    client      TEXT,
    scope_cidrs TEXT,
    scope_domains TEXT,
    scope_urls  TEXT,
    roe         TEXT,
    tester      TEXT,
    auth_ref    TEXT,
    status      TEXT DEFAULT 'active',
    phase       TEXT DEFAULT 'scoping',
    created_at  TEXT,
    updated_at  TEXT,
    -- Identity / OSINT scope (Phase 8 — person-OSINT). JSON arrays of
    -- normalized values (lowercased, stripped, leading '@' removed for handles).
    scope_emails          TEXT DEFAULT '[]',
    scope_usernames       TEXT DEFAULT '[]',
    scope_persons         TEXT DEFAULT '[]',
    scope_social_handles  TEXT DEFAULT '[]',
    osint_auth_ref        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    ip              TEXT NOT NULL,
    hostname        TEXT,
    os_guess        TEXT,
    status          TEXT DEFAULT 'up',
    tags            TEXT,
    discovered_at   TEXT,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS services (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         TEXT NOT NULL,
    port            INTEGER,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT,
    version         TEXT,
    banner          TEXT,
    detection_hints TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    engagement_id       TEXT NOT NULL,
    host_id             TEXT,
    severity            TEXT,
    category            TEXT,
    title               TEXT,
    description         TEXT,
    evidence            TEXT,
    cve                 TEXT,
    cvss_score          REAL DEFAULT 0.0,
    tool_used           TEXT,
    attack_path         TEXT,
    mitre_techniques    TEXT,
    remediation         TEXT,
    detection_rule      TEXT,
    hardening_steps     TEXT,
    created_at          TEXT,
    -- Adaptive grounding (Phase 2)
    confidence          REAL DEFAULT 0.5,
    confidence_rationale TEXT DEFAULT '',
    evidence_audit_ids  TEXT DEFAULT '[]',
    freshness_ts        TEXT,
    verification_count  INTEGER DEFAULT 0,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    host_id         TEXT,
    service         TEXT,
    username        TEXT,
    password_enc    TEXT,
    hash_enc        TEXT,
    hash_type       TEXT,
    cracked         INTEGER DEFAULT 0,
    notes           TEXT,
    created_at      TEXT,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
);
"""


class SessionStore:
    def __init__(self, db_path: str = "./sessions/assessments.db"):
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            # Enforce foreign-key constraints. Off by default in SQLite for
            # backward compatibility — without this, FOREIGN KEY clauses in
            # SCHEMA are advisory and orphan rows can be inserted. Enabling
            # it per-connection only blocks NEW violations; existing orphan
            # rows are not retroactively rejected.
            await db.execute("PRAGMA foreign_keys=ON")
            # WAL improves read concurrency (dashboard + agent loop both
            # read while the executor writes findings).
            try:
                await db.execute("PRAGMA journal_mode=WAL")
            except aiosqlite.Error:  # filesystem may not support WAL (e.g. tmpfs over NFS)
                pass
            # Wrap schema + migrations in a single immediate transaction so
            # an interrupted call to ``init`` cannot leave the DB in a
            # half-migrated state. ``BEGIN IMMEDIATE`` upgrades to a write
            # lock right away which prevents two concurrent migrators from
            # racing.
            await db.execute("BEGIN IMMEDIATE")
            try:
                await db.executescript(SCHEMA)
                await self._migrate_findings_adaptive(db)
                await self._migrate_engagements_identity(db)
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    @staticmethod
    async def _migrate_findings_adaptive(db) -> None:
        """Idempotent migration: add adaptive columns to legacy `findings` rows.

        Safe to call on fresh DBs (CREATE TABLE already includes the columns)
        and on legacy DBs that pre-date the adaptive extension.
        """
        db.row_factory = aiosqlite.Row
        async with db.execute("PRAGMA table_info(findings)") as cur:
            cols = {row["name"] for row in await cur.fetchall()}
        migrations = [
            ("confidence", "ALTER TABLE findings ADD COLUMN confidence REAL DEFAULT 0.5"),
            ("confidence_rationale", "ALTER TABLE findings ADD COLUMN confidence_rationale TEXT DEFAULT ''"),
            ("evidence_audit_ids", "ALTER TABLE findings ADD COLUMN evidence_audit_ids TEXT DEFAULT '[]'"),
            ("freshness_ts", "ALTER TABLE findings ADD COLUMN freshness_ts TEXT"),
            ("verification_count", "ALTER TABLE findings ADD COLUMN verification_count INTEGER DEFAULT 0"),
        ]
        for col, ddl in migrations:
            if col not in cols:
                await db.execute(ddl)
        db.row_factory = None

    @staticmethod
    async def _migrate_engagements_identity(db) -> None:
        """Idempotent migration: add identity scope columns to legacy
        ``engagements`` rows (Phase 8 — person-OSINT).

        Safe on fresh DBs (CREATE TABLE already includes them) and on
        legacy DBs that pre-date the identity extension.
        """
        db.row_factory = aiosqlite.Row
        async with db.execute("PRAGMA table_info(engagements)") as cur:
            cols = {row["name"] for row in await cur.fetchall()}
        migrations = [
            ("scope_emails", "ALTER TABLE engagements ADD COLUMN scope_emails TEXT DEFAULT '[]'"),
            ("scope_usernames", "ALTER TABLE engagements ADD COLUMN scope_usernames TEXT DEFAULT '[]'"),
            ("scope_persons", "ALTER TABLE engagements ADD COLUMN scope_persons TEXT DEFAULT '[]'"),
            ("scope_social_handles", "ALTER TABLE engagements ADD COLUMN scope_social_handles TEXT DEFAULT '[]'"),
            ("osint_auth_ref", "ALTER TABLE engagements ADD COLUMN osint_auth_ref TEXT DEFAULT ''"),
        ]
        for col, ddl in migrations:
            if col not in cols:
                await db.execute(ddl)
        db.row_factory = None

    # ── Engagements ──────────────────────────────────────

    async def create_engagement(self, eng: Engagement) -> Engagement:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO engagements
                   (id, name, client, scope_cidrs, scope_domains, scope_urls,
                    roe, tester, auth_ref, status, phase, created_at, updated_at,
                    scope_emails, scope_usernames, scope_persons,
                    scope_social_handles, osint_auth_ref)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    eng.id, eng.name, eng.client,
                    json.dumps(eng.scope_cidrs),
                    json.dumps(eng.scope_domains),
                    json.dumps(eng.scope_urls),
                    eng.rules_of_engagement,
                    eng.tester,
                    eng.authorization_ref,
                    eng.status.value,
                    eng.current_phase.value,
                    eng.created_at.isoformat(),
                    eng.updated_at.isoformat(),
                    json.dumps(eng.scope_emails),
                    json.dumps(eng.scope_usernames),
                    json.dumps(eng.scope_persons),
                    json.dumps(eng.scope_social_handles),
                    eng.osint_authorization_ref,
                ),
            )
            await db.commit()
        return eng

    async def get_engagement(self, eng_id: str) -> Engagement | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM engagements WHERE id = ?", (eng_id,)
            ) as cur:
                row = await cur.fetchone()
        if not row:
            return None
        return self._row_to_engagement(row)

    async def list_engagements(self) -> list[Engagement]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM engagements ORDER BY created_at DESC"
            ) as cur:
                rows = await cur.fetchall()
        return [self._row_to_engagement(r) for r in rows]

    async def update_engagement_phase(self, eng_id: str, phase: Phase) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE engagements SET phase=?, updated_at=? WHERE id=?",
                (phase.value, _sap_utcnow().isoformat(), eng_id),
            )
            await db.commit()

    async def update_engagement_status(self, eng_id: str, status: EngagementStatus) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE engagements SET status=?, updated_at=? WHERE id=?",
                (status.value, _sap_utcnow().isoformat(), eng_id),
            )
            await db.commit()

    async def update_engagement_identity(
        self,
        eng_id: str,
        *,
        osint_authorization_ref: str | None = None,
        scope_emails: list[str] | None = None,
        scope_usernames: list[str] | None = None,
        scope_persons: list[str] | None = None,
        scope_social_handles: list[str] | None = None,
        rules_of_engagement: str | None = None,
    ) -> None:
        """Patch identity scope and OSINT authorization on an existing engagement.

        Only fields explicitly provided (non-None) are updated. Lists are
        replaced wholesale (not appended). The Pydantic-side normalization
        of identity values must be applied by the caller.
        """
        sets: list[str] = []
        vals: list = []
        if osint_authorization_ref is not None:
            sets.append("osint_auth_ref=?")
            vals.append(osint_authorization_ref)
        if scope_emails is not None:
            sets.append("scope_emails=?")
            vals.append(json.dumps(scope_emails))
        if scope_usernames is not None:
            sets.append("scope_usernames=?")
            vals.append(json.dumps(scope_usernames))
        if scope_persons is not None:
            sets.append("scope_persons=?")
            vals.append(json.dumps(scope_persons))
        if scope_social_handles is not None:
            sets.append("scope_social_handles=?")
            vals.append(json.dumps(scope_social_handles))
        if rules_of_engagement is not None:
            sets.append("roe=?")
            vals.append(rules_of_engagement)
        if not sets:
            return
        sets.append("updated_at=?")
        vals.append(_sap_utcnow().isoformat())
        vals.append(eng_id)
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                f"UPDATE engagements SET {', '.join(sets)} WHERE id=?",  # noqa: S608
                tuple(vals),
            )
            await db.commit()

    # ── Hosts ────────────────────────────────────────────

    async def upsert_host(self, host: Host) -> Host:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO hosts
                   (id, engagement_id, ip, hostname, os_guess, status, tags, discovered_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                   hostname=excluded.hostname,
                   os_guess=excluded.os_guess,
                   status=excluded.status,
                   tags=excluded.tags""",
                (
                    host.id, host.engagement_id, host.ip,
                    host.hostname, host.os_guess, host.status,
                    json.dumps(host.tags),
                    host.discovered_at.isoformat(),
                ),
            )
            # Upsert services
            for svc in host.services:
                await db.execute(
                    """INSERT OR REPLACE INTO services
                       (host_id, port, protocol, service, version, banner, detection_hints)
                       VALUES (?,?,?,?,?,?,?)""",
                    (
                        host.id, svc.port, svc.protocol,
                        svc.service, svc.version, svc.banner,
                        json.dumps(svc.detection_hints),
                    ),
                )
            await db.commit()
        return host

    async def get_hosts(self, engagement_id: str) -> list[Host]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM hosts WHERE engagement_id=?", (engagement_id,)
            ) as cur:
                host_rows = await cur.fetchall()
            hosts = []
            for hr in host_rows:
                async with db.execute(
                    "SELECT * FROM services WHERE host_id=?", (hr["id"],)
                ) as scur:
                    svc_rows = await scur.fetchall()
                hosts.append(self._row_to_host(hr, svc_rows))
        return hosts

    # ── Findings ─────────────────────────────────────────

    async def add_finding(self, finding: Finding) -> Finding:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO findings
                   (id, engagement_id, host_id, severity, category, title,
                    description, evidence, cve, cvss_score, tool_used,
                    attack_path, mitre_techniques, remediation,
                    detection_rule, hardening_steps, created_at,
                    confidence, confidence_rationale, evidence_audit_ids,
                    freshness_ts, verification_count)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    finding.id, finding.engagement_id, finding.host_id,
                    finding.severity.value, finding.category.value,
                    finding.title, finding.description, finding.evidence,
                    finding.cve, finding.cvss_score, finding.tool_used,
                    finding.attack_path,
                    json.dumps(finding.mitre_techniques),
                    finding.remediation, finding.detection_rule,
                    json.dumps(finding.hardening_steps),
                    finding.created_at.isoformat(),
                    float(finding.confidence),
                    finding.confidence_rationale,
                    json.dumps(finding.evidence_audit_ids),
                    finding.freshness_ts.isoformat(),
                    int(finding.verification_count),
                ),
            )
            await db.commit()
        return finding

    async def get_findings(self, engagement_id: str) -> list[Finding]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM findings WHERE engagement_id=? ORDER BY cvss_score DESC",
                (engagement_id,),
            ) as cur:
                rows = await cur.fetchall()
        return [self._row_to_finding(r) for r in rows]

    async def get_finding(self, finding_id: str) -> Finding | None:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM findings WHERE id=?", (finding_id,)
            ) as cur:
                row = await cur.fetchone()
        return self._row_to_finding(row) if row else None

    async def update_finding_confidence(
        self,
        finding_id: str,
        *,
        new_confidence: float,
        rationale: str,
        freshness_ts: datetime,
        increment_verification: bool = True,
        reset_verification: bool = False,
    ) -> bool:
        """Persist a confidence update produced by the verification layer.

        Returns ``True`` when a row was actually updated. Caller is
        responsible for clamping ``new_confidence`` to [0, 1].
        """
        async with aiosqlite.connect(self._db_path) as db:
            if reset_verification:
                count_clause = "verification_count = 0"
                params: tuple = (
                    float(new_confidence), rationale, freshness_ts.isoformat(),
                    finding_id,
                )
            elif increment_verification:
                count_clause = "verification_count = verification_count + 1"
                params = (
                    float(new_confidence), rationale, freshness_ts.isoformat(),
                    finding_id,
                )
            else:
                count_clause = "verification_count = verification_count"
                params = (
                    float(new_confidence), rationale, freshness_ts.isoformat(),
                    finding_id,
                )
            cur = await db.execute(
                f"""UPDATE findings
                       SET confidence = ?,
                           confidence_rationale = ?,
                           freshness_ts = ?,
                           {count_clause}
                     WHERE id = ?""",  # noqa: S608 — count_clause is an internal template, never user-controlled
                params,
            )
            await db.commit()
            return cur.rowcount > 0


    # ── Credentials ──────────────────────────────────────

    async def add_credential(self, cred: Credential) -> Credential:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """INSERT INTO credentials
                   (id, engagement_id, host_id, service, username,
                    password_enc, hash_enc, hash_type, cracked, notes, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cred.id, cred.engagement_id, cred.host_id,
                    cred.service, cred.username,
                    _encrypt(cred.password),
                    _encrypt(cred.hash_value),
                    cred.hash_type,
                    int(cred.cracked),
                    cred.notes,
                    cred.created_at.isoformat(),
                ),
            )
            await db.commit()
        return cred

    async def get_credentials(self, engagement_id: str) -> list[Credential]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM credentials WHERE engagement_id=?", (engagement_id,)
            ) as cur:
                rows = await cur.fetchall()
        return [self._row_to_credential(r) for r in rows]

    # ── Bulk delete (used by dashboard reset/export workflows) ────

    async def delete_findings(self, engagement_id: str) -> int:
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute(
                "DELETE FROM findings WHERE engagement_id=?", (engagement_id,)
            )
            await db.commit()
            return cur.rowcount or 0

    async def delete_credentials(self, engagement_id: str) -> int:
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute(
                "DELETE FROM credentials WHERE engagement_id=?", (engagement_id,)
            )
            await db.commit()
            return cur.rowcount or 0

    async def delete_hosts(self, engagement_id: str) -> int:
        async with aiosqlite.connect(self._db_path) as db:
            # services FK by host_id; delete services first
            await db.execute(
                "DELETE FROM services WHERE host_id IN "
                "(SELECT id FROM hosts WHERE engagement_id=?)", (engagement_id,)
            )
            cur = await db.execute(
                "DELETE FROM hosts WHERE engagement_id=?", (engagement_id,)
            )
            await db.commit()
            return cur.rowcount or 0

    async def delete_engagement(self, engagement_id: str) -> bool:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "DELETE FROM services WHERE host_id IN "
                "(SELECT id FROM hosts WHERE engagement_id=?)", (engagement_id,)
            )
            await db.execute("DELETE FROM hosts       WHERE engagement_id=?", (engagement_id,))
            await db.execute("DELETE FROM findings    WHERE engagement_id=?", (engagement_id,))
            await db.execute("DELETE FROM credentials WHERE engagement_id=?", (engagement_id,))
            cur = await db.execute(
                "DELETE FROM engagements WHERE id=?", (engagement_id,)
            )
            await db.commit()
            return (cur.rowcount or 0) > 0

    # ── Private converters ────────────────────────────────

    @staticmethod
    def _row_to_engagement(row) -> Engagement:
        # Identity scope columns are added by an idempotent migration on
        # init(). Legacy rows / tests using sqlite3.Row need a defensive
        # lookup because Row does not support .get() — wrap in try/except.
        def _opt(col: str, default: str = "[]") -> str:
            try:
                val = row[col]
            except (KeyError, IndexError):
                return default
            return val if val is not None else default

        return Engagement(
            id=row["id"],
            name=row["name"],
            client=row["client"] or "",
            scope_cidrs=json.loads(row["scope_cidrs"] or "[]"),
            scope_domains=json.loads(row["scope_domains"] or "[]"),
            scope_urls=json.loads(row["scope_urls"] or "[]"),
            scope_emails=json.loads(_opt("scope_emails", "[]")),
            scope_usernames=json.loads(_opt("scope_usernames", "[]")),
            scope_persons=json.loads(_opt("scope_persons", "[]")),
            scope_social_handles=json.loads(_opt("scope_social_handles", "[]")),
            osint_authorization_ref=_opt("osint_auth_ref", "") or "",
            rules_of_engagement=row["roe"] or "",
            tester=row["tester"] or "",
            authorization_ref=row["auth_ref"] or "",
            status=EngagementStatus(row["status"]),
            current_phase=Phase(row["phase"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_host(hr, svc_rows) -> Host:
        services = [
            Service(
                port=s["port"],
                protocol=s["protocol"],
                service=s["service"] or "",
                version=s["version"] or "",
                banner=s["banner"] or "",
                detection_hints=json.loads(s["detection_hints"] or "[]"),
            )
            for s in svc_rows
        ]
        return Host(
            id=hr["id"],
            engagement_id=hr["engagement_id"],
            ip=hr["ip"],
            hostname=hr["hostname"] or "",
            os_guess=hr["os_guess"] or "",
            status=hr["status"],
            services=services,
            tags=json.loads(hr["tags"] or "[]"),
            discovered_at=datetime.fromisoformat(hr["discovered_at"]),
        )

    @staticmethod
    def _row_to_finding(row) -> Finding:
        from core.models import FindingCategory, Severity
        keys = row.keys() if hasattr(row, "keys") else []
        created_at = datetime.fromisoformat(row["created_at"])
        # Adaptive columns: tolerate legacy rows that pre-date the migration.
        confidence = row["confidence"] if "confidence" in keys and row["confidence"] is not None else 0.5
        rationale = row["confidence_rationale"] if "confidence_rationale" in keys and row["confidence_rationale"] is not None else ""
        evidence_ids_raw = row["evidence_audit_ids"] if "evidence_audit_ids" in keys and row["evidence_audit_ids"] is not None else "[]"
        try:
            evidence_ids = json.loads(evidence_ids_raw)
            if not isinstance(evidence_ids, list):
                evidence_ids = []
        except (TypeError, ValueError):
            evidence_ids = []
        freshness_raw = row["freshness_ts"] if "freshness_ts" in keys and row["freshness_ts"] else None
        try:
            freshness_ts = datetime.fromisoformat(freshness_raw) if freshness_raw else created_at
        except ValueError:
            freshness_ts = created_at
        verification_count = row["verification_count"] if "verification_count" in keys and row["verification_count"] is not None else 0
        return Finding(
            id=row["id"],
            engagement_id=row["engagement_id"],
            host_id=row["host_id"],
            severity=Severity(row["severity"]),
            category=FindingCategory(row["category"]),
            title=row["title"],
            description=row["description"] or "",
            evidence=row["evidence"] or "",
            cve=row["cve"] or "",
            cvss_score=row["cvss_score"] or 0.0,
            tool_used=row["tool_used"] or "",
            attack_path=row["attack_path"] or "",
            mitre_techniques=json.loads(row["mitre_techniques"] or "[]"),
            remediation=row["remediation"] or "",
            detection_rule=row["detection_rule"] or "",
            hardening_steps=json.loads(row["hardening_steps"] or "[]"),
            created_at=created_at,
            confidence=float(confidence),
            confidence_rationale=rationale,
            evidence_audit_ids=[str(x) for x in evidence_ids],
            freshness_ts=freshness_ts,
            verification_count=int(verification_count),
        )

    @staticmethod
    def _row_to_credential(row) -> Credential:
        return Credential(
            id=row["id"],
            engagement_id=row["engagement_id"],
            host_id=row["host_id"],
            service=row["service"] or "",
            username=row["username"] or "",
            password=_decrypt(row["password_enc"] or ""),
            hash_value=_decrypt(row["hash_enc"] or ""),
            hash_type=row["hash_type"] or "",
            cracked=bool(row["cracked"]),
            notes=row["notes"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
        )
