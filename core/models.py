"""
core/models.py — Pydantic data models for the Security Assessment Platform.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from core.time_utils import utcnow as _sap_utcnow

# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class FindingCategory(StrEnum):
    SQLI         = "sql_injection"
    RCE          = "remote_code_execution"
    LFI          = "local_file_inclusion"
    XSS          = "cross_site_scripting"
    OPEN_PORT    = "open_port"
    MISCONFIG    = "misconfiguration"
    WEAK_CREDS   = "weak_credentials"
    INFO_DISC    = "information_disclosure"
    CRYPTO_FAIL  = "cryptographic_failure"
    AUTH_BYPASS  = "authentication_bypass"
    PRIV_ESC     = "privilege_escalation"
    LATERAL_MOV  = "lateral_movement"
    AD_ATTACK    = "active_directory"
    OUTDATED_SW  = "outdated_software"
    OTHER        = "other"


class EngagementStatus(StrEnum):
    ACTIVE   = "active"
    PAUSED   = "paused"
    COMPLETE = "complete"
    ARCHIVED = "archived"


class Phase(StrEnum):
    SCOPING       = "scoping"
    RECON         = "reconnaissance"
    SCANNING      = "scanning"
    EXPLOITATION  = "exploitation"
    POST_EXPLOIT  = "post_exploitation"
    REPORTING     = "reporting"


# ─────────────────────────────────────────────
# Engagement / Scope
# ─────────────────────────────────────────────

class EngagementCreate(BaseModel):
    name: str
    client: str
    scope_cidrs: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_urls: list[str] = Field(default_factory=list)
    # ── Identity / OSINT scope (Phase 8 — person-OSINT capability) ──
    # These widen the engagement scope to *identity* targets (not infra).
    # Any tool from the OSINT MCP server requires the corresponding list to
    # contain the exact target value (case-insensitive, normalized) AND
    # ``osint_authorization_ref`` to be non-empty.
    scope_emails: list[str] = Field(default_factory=list)
    scope_usernames: list[str] = Field(default_factory=list)
    scope_persons: list[str] = Field(default_factory=list)
    scope_social_handles: list[str] = Field(default_factory=list)
    rules_of_engagement: str = ""
    tester: str = ""
    authorization_ref: str = Field(
        description="Reference to signed authorization document",
        default=""
    )
    osint_authorization_ref: str = Field(
        description=(
            "Separate authorization reference covering OSINT/PII targets "
            "(persons, emails, usernames, social handles). REQUIRED when any "
            "scope_emails/usernames/persons/social_handles is non-empty."
        ),
        default="",
    )

    # ── Identity normalizers ──────────────────────────────
    # Normalization rules (kept in sync with ``core.target_validator``):
    # - emails: lowercase, strip whitespace; basic shape check (one '@', dot in domain)
    # - usernames: strip whitespace, lowercase
    # - social handles: strip whitespace, drop leading '@', lowercase
    # - persons (real names): strip + collapse internal whitespace, casefold

    @field_validator("scope_emails", mode="before")
    @classmethod
    def _norm_emails(cls, v):
        if not v:
            return []
        out = []
        for raw in v:
            if not isinstance(raw, str):
                continue
            s = raw.strip().lower()
            if not s:
                continue
            # Minimal RFC-5322-lite shape check; full parsing happens
            # in ``core.target_validator.normalize_email``.
            if s.count("@") != 1 or "." not in s.split("@", 1)[1]:
                raise ValueError(f"invalid email in scope_emails: {raw!r}")
            out.append(s)
        return out

    @field_validator("scope_usernames", mode="before")
    @classmethod
    def _norm_usernames(cls, v):
        if not v:
            return []
        return [s.strip().lower() for s in v if isinstance(s, str) and s.strip()]

    @field_validator("scope_social_handles", mode="before")
    @classmethod
    def _norm_handles(cls, v):
        if not v:
            return []
        return [
            s.strip().lstrip("@").lower()
            for s in v if isinstance(s, str) and s.strip().lstrip("@")
        ]

    @field_validator("scope_persons", mode="before")
    @classmethod
    def _norm_persons(cls, v):
        if not v:
            return []
        out = []
        for raw in v:
            if not isinstance(raw, str):
                continue
            s = " ".join(raw.split()).casefold()
            if s:
                out.append(s)
        return out

    @model_validator(mode="after")
    def _warn_shared_authorization_ref(self):
        """Emit a stderr warning when infra and OSINT auth share the same
        reference — typically a misconfiguration that conflates two
        legally distinct authorizations. Non-blocking.
        """
        a = (self.authorization_ref or "").strip()
        b = (self.osint_authorization_ref or "").strip()
        if a and b and a == b:
            import sys as _sys
            _sys.stderr.write(
                "[engagement] warning: authorization_ref == osint_authorization_ref "
                f"({a!r}); OSINT/PII activities normally require a distinct ROE.\n"
            )
        return self


class Engagement(EngagementCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: EngagementStatus = EngagementStatus.ACTIVE
    current_phase: Phase = Phase.SCOPING
    created_at: datetime = Field(default_factory=_sap_utcnow)
    updated_at: datetime = Field(default_factory=_sap_utcnow)


# ─────────────────────────────────────────────
# Host / Service
# ─────────────────────────────────────────────

class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    # Blue team: alerts & detection hints for this service
    detection_hints: list[str] = Field(default_factory=list)


class Host(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    ip: str
    hostname: str = ""
    os_guess: str = ""
    status: str = "up"
    services: list[Service] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=_sap_utcnow)


# ─────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    host_id: str | None = None
    severity: Severity
    category: FindingCategory
    title: str
    description: str
    evidence: str = ""
    cve: str = ""
    cvss_score: float = 0.0
    tool_used: str = ""
    # Red Team
    attack_path: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    # Blue Team
    remediation: str = ""
    detection_rule: str = ""       # Sigma/YARA/Snort rule
    hardening_steps: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_sap_utcnow)
    # ── Adaptive grounding (Phase 2 – memory & verification) ──
    # Numeric confidence in [0.0, 1.0]; default 0.5 = "unverified".
    confidence: float = 0.5
    # Short rationale describing why the score was assigned (heuristics applied).
    confidence_rationale: str = ""
    # Audit-log entry IDs that produced the evidence supporting this finding.
    evidence_audit_ids: list[str] = Field(default_factory=list)
    # Last time the finding evidence was (re)verified. Defaults to creation time.
    freshness_ts: datetime = Field(default_factory=_sap_utcnow)
    # Increments on each successful re-verification; resets on drift.
    verification_count: int = 0


# ─────────────────────────────────────────────
# Credentials
# ─────────────────────────────────────────────

class Credential(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    host_id: str | None = None
    service: str = ""
    username: str = ""
    # raw fields stored ENCRYPTED in DB, exposed here as plaintext only in-memory
    password: str = ""
    hash_value: str = ""
    hash_type: str = ""
    cracked: bool = False
    notes: str = ""
    created_at: datetime = Field(default_factory=_sap_utcnow)


# ─────────────────────────────────────────────
# Tool Execution Result
# ─────────────────────────────────────────────

class ToolOutputRefModel(BaseModel):
    """Pydantic mirror of ``core.tool_output_store.ToolOutputRef``.

    Pointer to a persisted tool output blob. The full bytes live on the
    filesystem under ``sessions/runs/{run_id}/tool_outputs/{call_id}/``;
    this object is what gets carried in API responses.
    """
    call_id: str
    run_id: str
    engagement_id: str = ""
    tool: str
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_uri: str = ""
    stderr_uri: str = ""
    artifacts_uri: str = ""
    stdout_compressed: bool = False
    stderr_compressed: bool = False
    truncated_in_memory: bool = False


class ExecutionResult(BaseModel):
    tool: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_seconds: float
    truncated: bool = False
    engagement_id: str = ""
    phase: Phase = Phase.SCANNING
    timestamp: datetime = Field(default_factory=_sap_utcnow)
    # ── Canonical persistence (Phase 3 — tool output store) ──
    # Unique id for this execution; assigned by the executor before run().
    call_id: str = ""
    # Run id this execution belongs to (used to scope persisted outputs).
    run_id: str = ""
    # Reference to the persisted full output (set when the executor's
    # ToolOutputStore is enabled). When unset the legacy in-memory-only
    # behavior is preserved.
    output_ref: ToolOutputRefModel | None = None
    # Full byte counts as captured BEFORE any in-memory cap was applied.
    stdout_bytes_full: int = 0
    stderr_bytes_full: int = 0


# ─────────────────────────────────────────────
# Audit Log Entry
# ─────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str
    actor: str = "agent"
    action: str
    target: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_sap_utcnow)
