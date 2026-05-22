"""
mcp_servers/engagement_server.py — MCP Server: Engagement & Session Management.

This server manages the entire lifecycle of a security assessment engagement:
  - create / list / load engagements
  - validate and retrieve scope
  - update phase and status
  - store findings, hosts, credentials
  - retrieve session state (hosts found, findings so far)
"""
import sys
from pathlib import Path

# Ensure repo root is on path when run as subprocess
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()


from core.models import (
    AuditEntry,
    Credential,
    Engagement,
    EngagementCreate,
    EngagementStatus,
    Finding,
    FindingCategory,
    Host,
    Phase,
    Service,
    Severity,
)

# ── Singletons ───────────────────────────────────────────────────────────────
# v3.1 W1.4 — Bootstrap via BaseMCPServer so every MCP server in the process
# shares one ``AuditLog`` / ``SessionStore`` / ``ToolExecutor`` instance via
# the DI container. The previous per-server inline construction caused the
# BLAKE2b hash chain to fragment into one chain per server (forensic
# integrity risk). ``BaseMCPServer.from_env`` preserves the legacy env-var
# resolution (``SESSION_DB_PATH`` / ``AUDIT_LOG_PATH``) so existing on-disk
# state is read unchanged. Engagement server keeps only the resource
# handler (not the run-context tool) so the exposed MCP surface is
# identical to v3.0.
from mcp_servers.base import BaseMCPServer

_srv = BaseMCPServer.from_env(name="engagement")
store = _srv.store
audit = _srv.audit
mcp = _srv.mcp
from core.tool_output_store import get_tool_output_store
from mcp_servers._response import register_resource_handlers

register_resource_handlers(mcp, get_tool_output_store, server_suffix="engagement")


# ── Lifecycle initialiser ─────────────────────────────────────────────────────

@mcp.tool()
async def init_store() -> str:
    """Initialize the database schema. Call this once before using other tools."""
    await store.init()
    return "Database initialized."


# ── Engagement management ─────────────────────────────────────────────────────

@mcp.tool()
async def create_engagement(
    name: str,
    client: str,
    tester: str,
    authorization_ref: str,
    scope_cidrs: str = "",
    scope_domains: str = "",
    scope_urls: str = "",
    rules_of_engagement: str = "",
    osint_authorization_ref: str = "",
    scope_emails: str = "",
    scope_usernames: str = "",
    scope_persons: str = "",
    scope_social_handles: str = "",
) -> dict:
    """
    Create a new security assessment engagement.

    IMPORTANT: authorization_ref must reference a signed authorization document.
    Without authorization, no tools should be run against any target.

    For person/identity OSINT (sherlock, maigret, holehe, h8mail, ghunt,
    spiderfoot, recon-ng, whatsmyname, …) you MUST also provide:
      - ``osint_authorization_ref`` — separate signed ROE covering PII targets
      - at least one of ``scope_emails`` / ``scope_usernames`` /
        ``scope_persons`` / ``scope_social_handles`` (comma-separated)

    Args:
        name: Engagement name (e.g. "Q2-2026 Internal Network Assessment")
        client: Client / organization name
        tester: Lead tester name
        authorization_ref: Reference ID or path to signed authorization doc
        scope_cidrs: Comma-separated CIDRs in scope (e.g. "10.0.0.0/24,192.168.1.0/24")
        scope_domains: Comma-separated domains in scope (e.g. "example.com,app.example.com")
        scope_urls: Comma-separated URLs in scope (e.g. "https://app.example.com")
        rules_of_engagement: Free text RoE (e.g. "No DoS, no data exfiltration, business hours only")
        osint_authorization_ref: Separate ROE reference for identity/PII OSINT
        scope_emails: Comma-separated emails in identity scope
        scope_usernames: Comma-separated usernames in identity scope
        scope_persons: Comma-separated person names in identity scope
        scope_social_handles: Comma-separated social handles (with or without leading '@')
    """
    await store.init()

    cidrs    = [c.strip() for c in scope_cidrs.split(",")           if c.strip()]
    domains  = [d.strip() for d in scope_domains.split(",")         if d.strip()]
    urls     = [u.strip() for u in scope_urls.split(",")            if u.strip()]
    emails   = [s.strip() for s in scope_emails.split(",")          if s.strip()]
    unames   = [s.strip() for s in scope_usernames.split(",")       if s.strip()]
    persons  = [s.strip() for s in scope_persons.split(",")         if s.strip()]
    handles  = [s.strip() for s in scope_social_handles.split(",")  if s.strip()]

    has_identity = bool(emails or unames or persons or handles)
    if has_identity and not osint_authorization_ref.strip():
        return {
            "error": (
                "Identity scope provided but osint_authorization_ref is empty. "
                "Person/identity OSINT requires a separate signed ROE reference."
            )
        }

    eng = Engagement(
        **EngagementCreate(
            name=name,
            client=client,
            tester=tester,
            authorization_ref=authorization_ref,
            scope_cidrs=cidrs,
            scope_domains=domains,
            scope_urls=urls,
            scope_emails=emails,
            scope_usernames=unames,
            scope_persons=persons,
            scope_social_handles=handles,
            osint_authorization_ref=osint_authorization_ref.strip(),
            rules_of_engagement=rules_of_engagement,
        ).model_dump()
    )

    await store.create_engagement(eng)
    await audit.write(AuditEntry(
        engagement_id=eng.id,
        action="engagement_created",
        actor=tester or "agent",
        details={
            "name": name,
            "client": client,
            "auth_ref": authorization_ref,
            "osint_auth_ref": eng.osint_authorization_ref,
            "identity_scope": has_identity,
        },
    ))

    return {
        "engagement_id": eng.id,
        "name": eng.name,
        "status": eng.status.value,
        "scope_cidrs": cidrs,
        "scope_domains": domains,
        "scope_urls": urls,
        "scope_emails": eng.scope_emails,
        "scope_usernames": eng.scope_usernames,
        "scope_persons": eng.scope_persons,
        "scope_social_handles": eng.scope_social_handles,
        "osint_authorization_ref": eng.osint_authorization_ref,
        "message": "Engagement created. Proceed only against authorized targets.",
    }


@mcp.tool()
async def update_engagement(
    engagement_id: str,
    osint_authorization_ref: str = "",
    scope_emails: str = "",
    scope_usernames: str = "",
    scope_persons: str = "",
    scope_social_handles: str = "",
    rules_of_engagement: str = "",
    replace_identity_scope: bool = False,
) -> dict:
    """
    Patch identity scope and/or OSINT authorization on an existing engagement.

    Use this when you created an engagement without identity fields and now
    need to enable person/identity OSINT (sherlock, maigret, holehe, etc.).

    Behaviour:
      - Empty string arguments are ignored (left unchanged), EXCEPT when
        ``replace_identity_scope=True``: in that case empty values *clear*
        the corresponding list.
      - ``osint_authorization_ref`` is set only when non-empty (it cannot
        be cleared from this tool — that would silently disable OSINT).
      - Identity values are normalized by Pydantic (lowercase, strip '@', …).

    Args:
        engagement_id: target engagement UUID
        osint_authorization_ref: signed ROE reference for PII targets
        scope_emails: comma-separated emails
        scope_usernames: comma-separated usernames
        scope_persons: comma-separated person real names
        scope_social_handles: comma-separated handles ('@' optional)
        rules_of_engagement: replacement RoE text
        replace_identity_scope: if True, empty fields clear existing values
    """
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        return {"error": f"Engagement '{engagement_id}' not found."}

    def _split(s: str) -> list[str]:
        return [x.strip() for x in s.split(",") if x.strip()]

    raw_emails  = _split(scope_emails)
    raw_unames  = _split(scope_usernames)
    raw_persons = _split(scope_persons)
    raw_handles = _split(scope_social_handles)

    # Normalize via the EngagementCreate validators by round-tripping through
    # a throw-away instance (keeps a single source of truth).
    norm = EngagementCreate(
        name=eng.name,
        client=eng.client,
        authorization_ref=eng.authorization_ref,
        scope_emails=raw_emails,
        scope_usernames=raw_unames,
        scope_persons=raw_persons,
        scope_social_handles=raw_handles,
    )

    patch: dict = {}
    if osint_authorization_ref.strip():
        patch["osint_authorization_ref"] = osint_authorization_ref.strip()
    if replace_identity_scope or raw_emails:
        patch["scope_emails"] = norm.scope_emails
    if replace_identity_scope or raw_unames:
        patch["scope_usernames"] = norm.scope_usernames
    if replace_identity_scope or raw_persons:
        patch["scope_persons"] = norm.scope_persons
    if replace_identity_scope or raw_handles:
        patch["scope_social_handles"] = norm.scope_social_handles
    if rules_of_engagement:
        patch["rules_of_engagement"] = rules_of_engagement

    if not patch:
        return {"error": "No fields to update."}

    await store.update_engagement_identity(engagement_id, **patch)
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="engagement_updated",
        details={"fields": sorted(patch.keys())},
    ))

    updated = await store.get_engagement(engagement_id)
    return {
        "engagement_id": engagement_id,
        "updated_fields": sorted(patch.keys()),
        "osint_authorization_ref": updated.osint_authorization_ref,
        "scope_emails": updated.scope_emails,
        "scope_usernames": updated.scope_usernames,
        "scope_persons": updated.scope_persons,
        "scope_social_handles": updated.scope_social_handles,
    }


@mcp.tool()
async def list_engagements() -> list[dict]:
    """List all engagements stored in this session database."""
    await store.init()
    engs = await store.list_engagements()
    return [
        {
            "id": e.id,
            "name": e.name,
            "client": e.client,
            "status": e.status.value,
            "phase": e.current_phase.value,
            "created_at": e.created_at.isoformat(),
        }
        for e in engs
    ]


@mcp.tool()
async def get_engagement(engagement_id: str) -> dict:
    """
    Retrieve full engagement details including scope.
    Use this to understand what targets are authorized.
    """
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        return {"error": f"Engagement '{engagement_id}' not found."}
    return eng.model_dump(mode="json")


@mcp.tool()
async def set_phase(engagement_id: str, phase: str) -> str:
    """
    Update the current phase of an engagement.
    Valid phases: scoping, reconnaissance, scanning, exploitation, post_exploitation, reporting.
    """
    await store.init()
    try:
        p = Phase(phase)
    except ValueError:
        valid = [ph.value for ph in Phase]
        return f"Invalid phase '{phase}'. Valid values: {valid}"
    await store.update_engagement_phase(engagement_id, p)
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="phase_changed",
        details={"new_phase": phase},
    ))
    return f"Phase updated to '{phase}'."


@mcp.tool()
async def complete_engagement(engagement_id: str) -> str:
    """Mark an engagement as complete (no more tool execution allowed)."""
    await store.init()
    await store.update_engagement_status(engagement_id, EngagementStatus.COMPLETE)
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="engagement_completed",
        details={},
    ))
    return f"Engagement '{engagement_id}' marked as COMPLETE."


# ── Findings ──────────────────────────────────────────────────────────────────

@mcp.tool()
async def add_finding(
    engagement_id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    evidence: str = "",
    cve: str = "",
    cvss_score: float = 0.0,
    tool_used: str = "",
    host_id: str = "",
    attack_path: str = "",
    mitre_techniques: str = "",
    remediation: str = "",
    detection_rule: str = "",
    hardening_steps: str = "",
    confidence: float = 0.5,
    confidence_rationale: str = "",
    evidence_audit_ids: str = "",
) -> dict:
    """
    Record a security finding for both Red Team (evidence, attack path)
    and Blue Team (remediation, detection, hardening).

    Args:
        severity: critical / high / medium / low / info
        category: e.g. sql_injection, remote_code_execution, misconfiguration, weak_credentials...
        mitre_techniques: comma-separated ATT&CK IDs e.g. "T1190,T1046"
        hardening_steps: comma-separated hardening steps
        confidence: numeric grounding score in [0.0, 1.0]; default 0.5 = unverified.
            Use higher values only when evidence is reproducible (tool stdout,
            CVE match, multi-tool corroboration).
        confidence_rationale: short text justifying the confidence score.
        evidence_audit_ids: comma-separated AuditEntry IDs that produced the
            evidence (provenance trail). Required to claim confidence > 0.7.
    """
    await store.init()
    try:
        sev = Severity(severity)
    except ValueError:
        sev = Severity.INFO
    try:
        cat = FindingCategory(category)
    except ValueError:
        cat = FindingCategory.OTHER

    # Clamp adaptive fields defensively.
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.5
    conf = max(0.0, min(1.0, conf))
    audit_ids = [s.strip() for s in (evidence_audit_ids or "").split(",") if s.strip()]

    finding = Finding(
        engagement_id=engagement_id,
        host_id=host_id or None,
        severity=sev,
        category=cat,
        title=title,
        description=description,
        evidence=evidence,
        cve=cve,
        cvss_score=cvss_score,
        tool_used=tool_used,
        attack_path=attack_path,
        mitre_techniques=[t.strip() for t in mitre_techniques.split(",") if t.strip()],
        remediation=remediation,
        detection_rule=detection_rule,
        hardening_steps=[s.strip() for s in hardening_steps.split(",") if s.strip()],
        confidence=conf,
        confidence_rationale=confidence_rationale,
        evidence_audit_ids=audit_ids,
    )

    await store.add_finding(finding)
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="finding_added",
        details={
            "id": finding.id,
            "title": title,
            "severity": severity,
            "confidence": conf,
            "evidence_audit_ids": audit_ids,
        },
    ))
    return {
        "finding_id": finding.id,
        "title": title,
        "severity": severity,
        "confidence": conf,
    }


@mcp.tool()
async def get_findings(engagement_id: str) -> list[dict]:
    """Retrieve all findings for an engagement, ordered by CVSS score (highest first)."""
    await store.init()
    findings = await store.get_findings(engagement_id)
    return [f.model_dump(mode="json") for f in findings]


# ── Verification & operator feedback (Phase 5) ────────────────────────────────

@mcp.tool()
async def verify_finding(
    engagement_id: str,
    finding_id: str,
    outcome: str,
    new_evidence: str = "",
    drift_threshold: float = 0.15,
) -> dict:
    """Re-verify an existing finding and update its confidence in place.

    Args:
        engagement_id: Engagement that owns the finding (validated).
        finding_id: Target finding ID.
        outcome: ``confirmed`` | ``drift`` | ``inconclusive``. Drives the
            sign of the confidence delta (uses confirm_bonus / drift_penalty
            from config.yaml ``adaptive.verification``).
        new_evidence: Optional short text appended to the rationale so the
            human reviewer can audit *why* the verifier reached this outcome.
        drift_threshold: Absolute delta beyond which the result is logged
            as ``decision.drift_detected`` instead of plain
            ``decision.confidence_updated``.
    """
    from datetime import datetime as _dt

    from core.adaptive import (
        AdaptiveSettings,
        DecisionKind,
        emit_decision,
        load_adaptive_settings,
    )
    from core.adaptive.verification import apply_verification, build_manifest

    await store.init()
    finding = await store.get_finding(finding_id)
    if finding is None or finding.engagement_id != engagement_id:
        return {"error": "finding_not_found", "finding_id": finding_id}

    outcome_lc = (outcome or "").strip().lower()
    if outcome_lc not in {"confirmed", "drift", "inconclusive"}:
        return {
            "error": "invalid_outcome",
            "expected": ["confirmed", "drift", "inconclusive"],
        }

    settings: AdaptiveSettings = load_adaptive_settings()
    update = apply_verification(
        finding=finding,
        outcome=outcome_lc,  # type: ignore[arg-type]
        settings=settings,
        drift_threshold=float(drift_threshold),
    )
    manifest = build_manifest(finding)
    rationale_full = update.rationale
    if new_evidence:
        rationale_full = f"{update.rationale} :: {new_evidence[:240]}"

    now = _dt.utcnow()
    await store.update_finding_confidence(
        finding_id,
        new_confidence=update.new_value,
        rationale=rationale_full,
        freshness_ts=now,
        # Drift resets the verification counter — the finding has effectively
        # changed, so prior re-checks no longer count.
        increment_verification=not update.drift,
        reset_verification=update.drift,
    )

    kind = DecisionKind.DRIFT_DETECTED if update.drift else DecisionKind.CONFIDENCE_UPDATED
    summary = (
        f"verify[{outcome_lc}] {finding.title[:60]} "
        f"{update.previous:.2f} -> {update.new_value:.2f}"
    )
    await emit_decision(
        audit,
        engagement_id=engagement_id,
        kind=kind,
        summary=summary,
        target=finding_id,
        details={
            "finding_id": finding_id,
            "manifest_digest": manifest.digest,
            "manifest_components": manifest.components,
            "outcome": outcome_lc,
            **update.to_dict(),
        },
    )
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="finding_verified",
        details={
            "finding_id": finding_id,
            "outcome": outcome_lc,
            "manifest_digest": manifest.digest,
            **update.to_dict(),
        },
    ))
    return {
        "finding_id": finding_id,
        "outcome": outcome_lc,
        "manifest_digest": manifest.digest,
        **update.to_dict(),
    }


@mcp.tool()
async def operator_feedback(
    engagement_id: str,
    finding_id: str,
    kind: str,
    operator: str = "operator",
    comment: str = "",
) -> dict:
    """Apply operator feedback to a finding (manual confirm / refute / note).

    ``confirm`` boosts confidence by ``confirm_bonus``, ``refute`` lowers it
    by ``drift_penalty``, ``note`` is a zero-delta annotation that is still
    audit-emitted. The human reviewer is the only authority that can move
    a finding above the high-confidence threshold without an automated
    verification.
    """
    from datetime import datetime as _dt

    from core.adaptive import (
        AdaptiveSettings,
        DecisionKind,
        emit_decision,
        load_adaptive_settings,
    )
    from core.adaptive.verification import apply_operator_feedback, build_manifest

    await store.init()
    finding = await store.get_finding(finding_id)
    if finding is None or finding.engagement_id != engagement_id:
        return {"error": "finding_not_found", "finding_id": finding_id}

    kind_lc = (kind or "").strip().lower()
    if kind_lc not in {"confirm", "refute", "note"}:
        return {"error": "invalid_kind", "expected": ["confirm", "refute", "note"]}

    settings: AdaptiveSettings = load_adaptive_settings()
    update = apply_operator_feedback(
        finding=finding,
        kind=kind_lc,  # type: ignore[arg-type]
        settings=settings,
        operator=operator or "operator",
        comment=comment or None,
    )
    manifest = build_manifest(finding)

    now = _dt.utcnow()
    if kind_lc == "note":
        # Notes don't change the score, but we still bump freshness so
        # the dashboard can surface the most recently reviewed findings.
        await store.update_finding_confidence(
            finding_id,
            new_confidence=update.new_value,
            rationale=update.rationale,
            freshness_ts=now,
            increment_verification=False,
        )
    else:
        await store.update_finding_confidence(
            finding_id,
            new_confidence=update.new_value,
            rationale=update.rationale,
            freshness_ts=now,
            increment_verification=not update.drift,
            reset_verification=update.drift,
        )

    await emit_decision(
        audit,
        engagement_id=engagement_id,
        kind=DecisionKind.OPERATOR_FEEDBACK,
        summary=f"operator[{kind_lc}] by {operator} on {finding.title[:60]}",
        target=finding_id,
        actor=operator,
        details={
            "finding_id": finding_id,
            "manifest_digest": manifest.digest,
            "kind": kind_lc,
            "comment": comment,
            **update.to_dict(),
        },
    )
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="operator_feedback",
        actor=operator,
        details={
            "finding_id": finding_id,
            "kind": kind_lc,
            "comment": comment,
            **update.to_dict(),
        },
    ))
    return {
        "finding_id": finding_id,
        "kind": kind_lc,
        "manifest_digest": manifest.digest,
        **update.to_dict(),
    }



# ── Hosts ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def add_host(
    engagement_id: str,
    ip: str,
    hostname: str = "",
    os_guess: str = "",
    services_json: str = "[]",
    tags: str = "",
) -> dict:
    """
    Record a discovered host in the engagement session.

    Args:
        services_json: JSON array of service objects with keys:
                       port, protocol, service, version, banner
        tags: comma-separated labels e.g. "web-server,dc,linux"
    """
    await store.init()
    import json as _json
    raw_services = _json.loads(services_json)
    services = [
        Service(
            port=s.get("port", 0),
            protocol=s.get("protocol", "tcp"),
            service=s.get("service", ""),
            version=s.get("version", ""),
            banner=s.get("banner", ""),
        )
        for s in raw_services
    ]
    host = Host(
        engagement_id=engagement_id,
        ip=ip,
        hostname=hostname,
        os_guess=os_guess,
        services=services,
        tags=[t.strip() for t in tags.split(",") if t.strip()],
    )
    await store.upsert_host(host)
    return {"host_id": host.id, "ip": ip, "services_count": len(services)}


@mcp.tool()
async def get_hosts(engagement_id: str) -> list[dict]:
    """Get all discovered hosts for an engagement."""
    await store.init()
    hosts = await store.get_hosts(engagement_id)
    return [h.model_dump(mode="json") for h in hosts]


# ── Credentials ───────────────────────────────────────────────────────────────

@mcp.tool()
async def add_credential(
    engagement_id: str,
    service: str,
    username: str,
    password: str = "",
    hash_value: str = "",
    hash_type: str = "",
    host_id: str = "",
    notes: str = "",
) -> dict:
    """
    Record a discovered credential. Stored AES-256-GCM encrypted at rest.

    Args:
        service: e.g. "ssh", "smb", "http", "ldap"
        hash_type: e.g. "ntlm", "md5", "sha256", "kerberos5-tgs"
    """
    await store.init()
    cred = Credential(
        engagement_id=engagement_id,
        host_id=host_id or None,
        service=service,
        username=username,
        password=password,
        hash_value=hash_value,
        hash_type=hash_type,
        notes=notes,
    )
    await store.add_credential(cred)
    await audit.write(AuditEntry(
        engagement_id=engagement_id,
        action="credential_stored",
        details={"service": service, "username": username, "hash_type": hash_type},
    ))
    return {"credential_id": cred.id, "username": username, "service": service}


@mcp.tool()
async def get_credentials(engagement_id: str) -> list[dict]:
    """Retrieve all credentials for an engagement (passwords/hashes decrypted in memory)."""
    await store.init()
    creds = await store.get_credentials(engagement_id)
    return [c.model_dump(mode="json") for c in creds]


# ── Audit ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def get_audit_log(engagement_id: str) -> list[dict]:
    """Return all audit entries for an engagement."""
    entries = await audit.read_all(engagement_id=engagement_id)
    return [e.model_dump(mode="json") for e in entries]


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
