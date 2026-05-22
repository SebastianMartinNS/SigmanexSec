"""
mcp_servers/blueteam_server.py — MCP Server: Blue Team Analysis & Defense.

This server is the unique differentiator of the platform.
It takes raw findings and tool output, and generates:

  1. Sigma detection rules  — ready to import into any SIEM
  2. MITRE ATT&CK mapping   — technique → detection → mitigation
  3. Hardening recommendations — OS, service, configuration specific
  4. Firewall rules           — iptables/nftables/UFW
  5. Incident Response notes  — what an IR team should look for
  6. Executive summary        — risk narrative for management
  7. Full dual-perspective report (Red findings + Blue defenses)

The LLM is used extensively here to generate high-quality,
contextual remediation text and detection rules.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv

load_dotenv()


from core.models import Severity

# v3.1 W1.4 — shared SessionStore via DI container. Blueteam server does
# not expose tool-execution (no ``audit``/``_exe``/run-context tool), so
# we keep only the resource handler that v3.0 had.
from mcp_servers.base import BaseMCPServer

_srv  = BaseMCPServer.from_env(name="blueteam")
store = _srv.store
mcp   = _srv.mcp
from core.time_utils import utcnow as _sap_utcnow
from core.tool_output_store import get_tool_output_store
from mcp_servers._response import register_resource_handlers

register_resource_handlers(mcp, get_tool_output_store, server_suffix="blueteam")


# ── Static knowledge bases ────────────────────────────────────────────────────

# MITRE ATT&CK Technique → {detection_data_sources, default_mitigations}
MITRE_KB: dict[str, dict] = {
    "T1046": {
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "data_sources": ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Connection Creation"],
        "mitigations": ["M1030: Network Segmentation", "M1037: Filter Network Traffic"],
        "sigma_template": "network_scan",
    },
    "T1190": {
        "technique": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "data_sources": ["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
        "mitigations": ["M1048: Application Isolation and Sandboxing", "M1050: Exploit Protection", "M1051: Update Software"],
        "sigma_template": "web_exploit",
    },
    "T1110": {
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "data_sources": ["User Account: User Account Authentication"],
        "mitigations": ["M1036: Account Use Policies", "M1032: Multi-factor Authentication", "M1027: Password Policies"],
        "sigma_template": "brute_force",
    },
    "T1078": {
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Initial Access",
        "data_sources": ["User Account: User Account Authentication", "Logon Session: Logon Session Creation"],
        "mitigations": ["M1027: Password Policies", "M1032: Multi-factor Authentication"],
        "sigma_template": "valid_accounts",
    },
    "T1021.002": {
        "technique": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "data_sources": ["Network Share: Network Share Access", "Logon Session: Logon Session Creation"],
        "mitigations": ["M1035: Limit Access to Resource Over Network", "M1037: Filter Network Traffic"],
        "sigma_template": "lateral_smb",
    },
    "T1558.003": {
        "technique": "Kerberoasting",
        "tactic": "Credential Access",
        "data_sources": ["Active Directory: Active Directory Credential Request"],
        "mitigations": ["M1027: Password Policies", "M1041: Encrypt Sensitive Information"],
        "sigma_template": "kerberoasting",
    },
    "T1003": {
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "data_sources": ["Process: Process Access", "File: File Access", "Windows Registry: Windows Registry Key Access"],
        "mitigations": ["M1043: Credential Access Protection", "M1017: User Training", "M1026: Privileged Account Management"],
        "sigma_template": "credential_dump",
    },
    "T1595": {
        "technique": "Active Scanning",
        "tactic": "Reconnaissance",
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1056: Pre-compromise"],
        "sigma_template": "active_scanning",
    },
}


# Pre-built Sigma rule templates
SIGMA_TEMPLATES: dict[str, str] = {
    "network_scan": """\
title: Network Port Scanning Detected
id: {rule_id}
status: experimental
description: Detects rapid sequential connection attempts to multiple ports — indicative of port scanning activity (T1046).
references:
  - https://attack.mitre.org/techniques/T1046/
author: Security Assessment Platform
date: {date}
tags:
  - attack.reconnaissance
  - attack.t1046
logsource:
  product: firewall
detection:
  selection:
    dst_ip: '{target}'
  condition: selection | count(dst_port) by src_ip > 100
  timeframe: 60s
falsepositives:
  - Authorized vulnerability scanners
  - Network monitoring systems
level: medium
""",
    "brute_force": """\
title: Brute Force Login Attempt Detected
id: {rule_id}
status: experimental
description: Multiple failed authentication attempts from a single source — indicative of T1110 (Brute Force).
references:
  - https://attack.mitre.org/techniques/T1110/
author: Security Assessment Platform
date: {date}
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4625
      - 4771
    IpAddress: '{src_ip}'
  condition: selection | count() > 10
  timeframe: 5m
falsepositives:
  - Misconfigured applications
  - Password rotation scripts
level: high
""",
    "kerberoasting": """\
title: Kerberoasting TGS Request Detected
id: {rule_id}
status: experimental
description: Multiple TGS-REQ for service accounts in a short period — indicative of Kerberoasting (T1558.003).
references:
  - https://attack.mitre.org/techniques/T1558/003/
author: Security Assessment Platform
date: {date}
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'    # RC4 — old encryption often targeted
  condition: selection | count() by RequestorName > 5
  timeframe: 10m
falsepositives:
  - Legacy applications using RC4
level: high
""",
    "lateral_smb": """\
title: Lateral Movement via SMB/Admin Share Detected
id: {rule_id}
status: experimental
description: Detects SMB connections to admin shares (C$, ADMIN$, IPC$) from non-admin workstations.
references:
  - https://attack.mitre.org/techniques/T1021/002/
author: Security Assessment Platform
date: {date}
tags:
  - attack.lateral_movement
  - attack.t1021.002
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5140
    ShareName|contains:
      - 'C$'
      - 'ADMIN$'
      - 'IPC$'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
  - Authorized system administration
  - Backup agents
level: high
""",
    "web_exploit": """\
title: Web Application Exploitation Attempt
id: {rule_id}
status: experimental
description: Detects common injection patterns in HTTP requests targeting web applications (T1190).
references:
  - https://attack.mitre.org/techniques/T1190/
author: Security Assessment Platform
date: {date}
tags:
  - attack.initial_access
  - attack.t1190
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|contains:
      - "' OR "
      - "UNION SELECT"
      - "../../../"
      - "<script>"
      - "exec("
      - "/etc/passwd"
  condition: selection
falsepositives:
  - Security scanners
  - Web application testing
level: high
""",
    "credential_dump": """\
title: Credential Dumping Activity Detected
id: {rule_id}
status: experimental
description: Detects access to LSASS process memory or SAM database — indicative of T1003.
references:
  - https://attack.mitre.org/techniques/T1003/
author: Security Assessment Platform
date: {date}
tags:
  - attack.credential_access
  - attack.t1003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4656
    ObjectName|contains:
      - 'lsass.exe'
      - 'SYSTEM\\\\CurrentControlSet\\\\Services\\\\NTDS'
  condition: selection
falsepositives:
  - AV/EDR software
  - Authorized memory analysis tools
level: critical
""",
}


def _new_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
async def generate_sigma_rule(
    engagement_id: str,
    technique_id: str,
    target: str = "",
    src_ip: str = "",
) -> dict:
    """
    Generate a Sigma detection rule for a given MITRE ATT&CK technique.
    Rules are ready to import into Splunk, Elastic, QRadar, Sentinel, or any SIEM.

    Args:
        technique_id: MITRE ATT&CK technique ID e.g. "T1046", "T1558.003", "T1110"
        target: Target IP/hostname to embed in the rule (optional)
        src_ip: Attacker source IP for brute-force rules (optional)
    Returns:
        Sigma rule in YAML format + ATT&CK context.
    """
    kb = MITRE_KB.get(technique_id)
    if not kb:
        # Return generic rule
        return {
            "technique_id": technique_id,
            "sigma_rule": f"# No template for {technique_id}. Consult https://github.com/SigmaHQ/sigma",
            "note": "Technique not in built-in knowledge base. Use the LLM to generate a custom rule.",
        }

    template_key = kb.get("sigma_template", "")
    template = SIGMA_TEMPLATES.get(template_key, "")
    rule = template.format(
        rule_id=_new_uuid(),
        date=_sap_utcnow().strftime("%Y/%m/%d"),
        target=target or "REPLACE_WITH_TARGET",
        src_ip=src_ip or "REPLACE_WITH_SRC",
    )

    return {
        "technique_id": technique_id,
        "technique_name": kb["technique"],
        "tactic": kb["tactic"],
        "sigma_rule": rule,
        "data_sources": kb["data_sources"],
        "mitigations": kb["mitigations"],
    }


@mcp.tool()
async def get_hardening_recommendations(
    service: str,
    os_type: str = "linux",
    version: str = "",
) -> dict:
    """
    Get specific hardening recommendations for a discovered service.

    Args:
        service: e.g. ssh, smb, rdp, http, https, ftp, mysql, mssql, ldap, snmp
        os_type: linux, windows, macos
        version: Optional version string for version-specific recommendations
    Returns:
        Structured hardening checklist with configuration examples.
    """
    recommendations: dict[str, dict] = {
        "ssh": {
            "title": "SSH Hardening",
            "critical_steps": [
                "Disable root login: PermitRootLogin no",
                "Use key-based auth only: PasswordAuthentication no",
                "Restrict to specific users: AllowUsers <user1> <user2>",
                "Change default port (security through obscurity, not sufficient alone)",
                "Enable fail2ban or similar brute-force protection",
            ],
            "config_example": """\
# /etc/ssh/sshd_config (minimum hardening)
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers deploy admin
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
""",
            "detection": "Monitor /var/log/auth.log for repeated failures (EventID 4625 on Windows).",
        },
        "smb": {
            "title": "SMB/Samba Hardening",
            "critical_steps": [
                "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                "Require SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true",
                "Disable guest access: net use \\\\server\\IPC$ /user:Guest => blocked",
                "Restrict admin shares: Block C$, ADMIN$ from normal users",
                "Enable Windows Firewall rules blocking inbound 445 from untrusted networks",
            ],
            "config_example": """\
# PowerShell — apply on all Windows hosts
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
""",
            "detection": "Audit EventID 5140 (share access) and 4625 (failed logon) in Windows Security log.",
        },
        "rdp": {
            "title": "RDP Hardening",
            "critical_steps": [
                "Restrict RDP access to VPN/jump host only (firewall rule)",
                "Enable Network Level Authentication (NLA)",
                "Enable account lockout policy (5 attempts, 30 min lockout)",
                "Use MFA for RDP: Azure AD / Duo / RADIUS",
                "Disable RDP if not strictly needed",
            ],
            "config_example": """\
# PowerShell
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1  # NLA
# Firewall — allow only from VPN range
New-NetFirewallRule -DisplayName "RDP-VPN-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress 10.0.0.0/8 -Action Allow
""",
            "detection": "Monitor EventID 4624 (successful logon type 10/3) and 4625 failures from external IPs.",
        },
        "snmp": {
            "title": "SNMP Hardening",
            "critical_steps": [
                "Change default community strings (public/private) immediately",
                "Use SNMPv3 with authentication and privacy (AES/SHA)",
                "Restrict SNMP access to monitoring IPs only (ACL)",
                "Disable SNMP if not needed",
                "Regularly audit SNMP community strings",
            ],
            "detection": "Alert on SNMP requests from unauthorized source IPs.",
        },
        "http": {
            "title": "Web Server Hardening",
            "critical_steps": [
                "Update web framework/CMS to latest patched version",
                "Remove/disable directory listing: Options -Indexes",
                "Add security headers: X-Frame-Options, CSP, HSTS, X-Content-Type-Options",
                "Disable verbose error messages in production",
                "Implement WAF (ModSecurity, AWS WAF, Cloudflare)",
                "Rate-limit authentication endpoints",
            ],
            "config_example": """\
# Nginx security headers (add to server block)
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
server_tokens off;
""",
            "detection": "WAF logs, access log analysis for 40x storms, SQLi/XSS patterns.",
        },
        "ldap": {
            "title": "LDAP / Active Directory Hardening",
            "critical_steps": [
                "Enforce LDAP signing (prevent LDAP relay attacks)",
                "Enable LDAPS (TLS) and disable plaintext LDAP port 389",
                "Apply fine-grained password policies (FGPP) for service accounts",
                "Enable Protected Users security group for sensitive accounts",
                "Tiered admin model: Tier 0 (DC), Tier 1 (Servers), Tier 2 (Workstations)",
                "Run BloodHound regularly to find attack paths and remediate",
            ],
            "detection": "Monitor AD event logs: 4769 (TGS), 4776 (NTLM auth), 4768 (TGT), 4625 (failures).",
        },
    }

    rec = recommendations.get(service.lower(), {
        "title": f"{service.upper()} Hardening",
        "critical_steps": [
            f"Update {service} to the latest patched version",
            f"Restrict {service} access to authorized networks only (firewall)",
            f"Enable authentication/encryption for {service} if supported",
            f"Audit {service} logs for anomalous access patterns",
        ],
        "detection": f"Enable logging for {service} and forward to SIEM.",
    })

    return {
        "service": service,
        "os_type": os_type,
        **rec,
    }


@mcp.tool()
async def generate_firewall_rules(
    engagement_id: str,
    hosts_json: str,
    rule_type: str = "iptables",
) -> dict:
    """
    Generate firewall rules to block/restrict attack paths found during assessment.

    Args:
        hosts_json: JSON array of host objects from get_hosts() — use their open ports
        rule_type: iptables, nftables, ufw, windows-firewall
    Returns:
        Ready-to-apply firewall rules for each discovered host.
    """
    await store.init()
    hosts = json.loads(hosts_json)
    rules = []

    header = {
        "iptables": "#!/bin/bash\n# Generated by Security Assessment Platform\n# REVIEW BEFORE APPLYING\n\n",
        "ufw": "# UFW rules — run as root\n",
        "nftables": "#!/usr/sbin/nft -f\n# nftables rules\n\n",
    }.get(rule_type, "# Firewall rules\n")

    for host in hosts:
        ip = host.get("ip", "")
        services_data = host.get("services", [])

        host_rules = [f"\n# ── Host: {ip} ──"]
        for svc in services_data:
            port = svc.get("port")
            proto = svc.get("protocol", "tcp")
            svc_name = svc.get("service", "unknown")

            if rule_type == "iptables":
                # Allow only from management network 10.0.0.0/8, block rest
                host_rules.append(
                    f"iptables -A INPUT -p {proto} --dport {port} -s 10.0.0.0/8 -j ACCEPT  # {svc_name}"
                )
                host_rules.append(
                    f"iptables -A INPUT -p {proto} --dport {port} -j DROP"
                )
            elif rule_type == "ufw":
                host_rules.append(f"ufw allow from 10.0.0.0/8 to any port {port} proto {proto}  # {svc_name}")
                host_rules.append(f"ufw deny {port}/{proto}")
            elif rule_type == "nftables":
                host_rules.append(
                    f"  tcp dport {port} ip saddr 10.0.0.0/8 accept  # {svc_name} on {ip}"
                )

        rules.extend(host_rules)

    return {
        "rule_type": rule_type,
        "rules": header + "\n".join(rules),
        "note": "IMPORTANT: Review and adapt these rules to your specific network before applying. Test in staging first.",
    }


@mcp.tool()
async def generate_ir_playbook(
    technique_id: str,
    context: str = "",
) -> dict:
    """
    Generate an Incident Response (IR) playbook for a detected ATT&CK technique.
    Helps Blue Team respond if the discovered attack vector is exploited.

    Args:
        technique_id: MITRE ATT&CK technique ID
        context: Additional context from the assessment (optional)
    Returns:
        Structured IR playbook with detection, containment, eradication, recovery steps.
    """
    playbooks: dict[str, dict] = {
        "T1046": {
            "title": "Network Scanning IR Playbook",
            "detect": [
                "Review firewall/IDS logs for portscanning signatures",
                "Identify source IP and correlate with known scanners",
                "Check if source is internal (lateral movement) or external (perimeter breach)",
            ],
            "contain": [
                "Block source IP at perimeter firewall (if external)",
                "If internal: isolate source host from network",
                "Enable rate-limiting on switches/firewalls",
            ],
            "eradicate": [
                "Identify and remove unauthorized scanner tool from compromised host",
                "Reset credentials of compromised account used to install scanner",
            ],
            "recover": [
                "Patch any vulnerabilities discovered during attacker scan",
                "Document scanning activity and update threat intelligence",
            ],
        },
        "T1558.003": {
            "title": "Kerberoasting IR Playbook",
            "detect": [
                "Query AD for EventID 4769 (TGS-REQ) with RC4 encryption (type 0x17)",
                "Alert on multiple TGS requests from single account in short period",
                "Review accounts that requested tickets: are they normal users?",
            ],
            "contain": [
                "Identify which service account tickets were requested",
                "Immediately reset passwords for affected service accounts (>25 char, random)",
                "Disable the account used to perform Kerberoasting",
            ],
            "eradicate": [
                "Rotate ALL service account passwords (attacker may have obtained others offline)",
                "Migrate service accounts to Group Managed Service Accounts (gMSA)",
                "Remove unnecessary SPNs from user accounts",
            ],
            "recover": [
                "Audit all SPNs in the domain: Get-ADUser -Filter {ServicePrincipalName -ne \"$null\"}",
                "Implement tiered administration model",
                "Deploy honeytoken service accounts to detect future Kerberoasting",
            ],
        },
        "T1003": {
            "title": "Credential Dumping IR Playbook",
            "detect": [
                "LSASS process access: EventID 10 (Sysmon), EventID 4656 (Windows Security)",
                "Unusual process accessing LSASS: check for non-standard parent processes",
                "SAM registry key access attempts",
            ],
            "contain": [
                "Isolate affected host immediately",
                "Revoke all credentials from compromised host (passwords, Kerberos tickets, certificates)",
                "Force password reset for all accounts that logged into this host",
            ],
            "eradicate": [
                "Re-image the compromised host",
                "Rotate krbtgt password TWICE (24h apart) if DC was compromised",
                "Revoke and reissue certificates if PKI compromise suspected",
            ],
            "recover": [
                "Enable Credential Guard on all Windows 10/11 hosts",
                "Enable Protected Users security group for privileged accounts",
                "Deploy EDR/AV solution to detect LSASS access patterns",
            ],
        },
    }

    pb = playbooks.get(technique_id, {
        "title": f"IR Playbook for {technique_id}",
        "detect": ["Review logs for indicators of technique usage"],
        "contain": ["Isolate affected systems", "Block attacker source IP/account"],
        "eradicate": ["Remove attack tools", "Reset compromised credentials"],
        "recover": ["Patch underlying vulnerability", "Monitor for recurrence"],
    })

    if context:
        pb["assessment_context"] = context

    return pb


@mcp.tool()
async def generate_assessment_report(
    engagement_id: str,
    format_type: str = "markdown",
) -> dict:
    """
    Generate a full dual-perspective security assessment report.

    The report includes:
    - Executive Summary (management-facing risk narrative)
    - Red Team Findings (attack evidence, CVSS scores, PoC)
    - Blue Team Recommendations (per-finding remediation + detection rules)
    - MITRE ATT&CK heatmap (text representation)
    - Hardening Roadmap (prioritized remediation plan)

    Args:
        format_type: "markdown" (default) or "json"
    """
    await store.init()

    eng = await store.get_engagement(engagement_id)
    if not eng:
        return {"error": f"Engagement '{engagement_id}' not found."}

    findings = await store.get_findings(engagement_id)
    hosts    = await store.get_hosts(engagement_id)
    creds    = await store.get_credentials(engagement_id)

    # Severity counts
    sev_counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev_counts[f.severity.value] += 1

    # Unique MITRE techniques
    all_techniques: set[str] = set()
    for f in findings:
        all_techniques.update(f.mitre_techniques)

    if format_type == "json":
        return {
            "engagement": eng.model_dump(mode="json"),
            "summary": {
                "hosts_discovered": len(hosts),
                "total_findings": len(findings),
                "severity_breakdown": sev_counts,
                "credentials_found": len(creds),
                "mitre_techniques": sorted(all_techniques),
            },
            "findings": [f.model_dump(mode="json") for f in findings],
            "hosts": [h.model_dump(mode="json") for h in hosts],
        }

    # ── Markdown report ───────────────────────────────────────────────────────
    now = _sap_utcnow().strftime("%Y-%m-%d %H:%M UTC")
    risk_level = (
        "CRITICAL" if sev_counts["critical"] > 0 else
        "HIGH"     if sev_counts["high"] > 0 else
        "MEDIUM"   if sev_counts["medium"] > 0 else
        "LOW"
    )

    md = f"""# Security Assessment Report
**Engagement:** {eng.name}  
**Client:** {eng.client}  
**Tester:** {eng.tester}  
**Date:** {now}  
**Overall Risk:** {risk_level}  
**Authorization Ref:** {eng.authorization_ref}

---

## Executive Summary

This security assessment of **{eng.client}** identified **{len(findings)} findings**
across **{len(hosts)} discovered hosts**.

| Severity | Count |
|----------|-------|
| 🔴 Critical | {sev_counts['critical']} |
| 🟠 High | {sev_counts['high']} |
| 🟡 Medium | {sev_counts['medium']} |
| 🔵 Low | {sev_counts['low']} |
| ⚪ Info | {sev_counts['info']} |

**Credentials Discovered:** {len(creds)}  
**MITRE ATT&CK Techniques Observed:** {len(all_techniques)}

---

## Scope

**Authorized CIDRs:** {', '.join(eng.scope_cidrs) or 'N/A'}  
**Authorized Domains:** {', '.join(eng.scope_domains) or 'N/A'}  
**Rules of Engagement:** {eng.rules_of_engagement or 'N/A'}

---

## Discovered Hosts

| IP | Hostname | OS | Open Ports |
|----|----------|----|------------|
"""
    for h in hosts:
        ports = ", ".join(str(s.port) for s in h.services[:10])
        md += f"| {h.ip} | {h.hostname or '-'} | {h.os_guess or 'Unknown'} | {ports} |\n"

    md += "\n---\n\n## Findings\n\n"

    for i, finding in enumerate(findings, 1):
        severity_badge = {
            "critical": "🔴", "high": "🟠", "medium": "🟡",
            "low": "🔵", "info": "⚪"
        }.get(finding.severity.value, "⚪")

        md += f"""### {i}. {severity_badge} [{finding.severity.value.upper()}] {finding.title}

**CVSS Score:** {finding.cvss_score}  
**Category:** {finding.category.value}  
**Tool Used:** {finding.tool_used or 'Manual'}  
**CVE:** {finding.cve or 'N/A'}  
**MITRE ATT&CK:** {', '.join(finding.mitre_techniques) or 'N/A'}

#### Description
{finding.description}

#### Evidence
```
{finding.evidence or 'See engagement notes.'}
```

#### 🗡️ Red Team — Attack Path
{finding.attack_path or 'N/A'}

#### 🛡️ Blue Team — Remediation
{finding.remediation or 'Refer to vendor security advisory.'}

#### 🔍 Blue Team — Detection Rule
```yaml
{finding.detection_rule or '# No detection rule generated. Use generate_sigma_rule tool.'}
```

#### ✅ Hardening Steps
"""
        for step in (finding.hardening_steps or ["Review vendor hardening guide."]):
            md += f"- {step}\n"
        md += "\n---\n\n"

    md += """## MITRE ATT&CK Techniques Observed

| Technique ID | Technique Name | Tactic |
|--------------|---------------|--------|
"""
    for tid in sorted(all_techniques):
        kb = MITRE_KB.get(tid, {})
        md += f"| {tid} | {kb.get('technique', 'Unknown')} | {kb.get('tactic', 'Unknown')} |\n"

    md += f"""
---

## Remediation Roadmap (Priority Order)

1. **Immediate (0-7 days):** Address all CRITICAL and HIGH findings, rotate exposed credentials.
2. **Short-term (7-30 days):** Address MEDIUM findings, implement detection rules in SIEM.
3. **Medium-term (30-90 days):** Address LOW findings, implement hardening recommendations.
4. **Ongoing:** Regular vulnerability assessments, patch management, security awareness training.

---

*Report generated by Security Assessment Platform on {now}.*  
*This report is confidential and intended only for authorized personnel.*
"""

    # Save report to file
    reports_dir = Path(os.environ.get("REPORTS_DIR", "./reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / f"{engagement_id}_{_sap_utcnow().strftime('%Y%m%d_%H%M%S')}.md"
    report_file.write_text(md, encoding="utf-8")

    return {
        "report": md,
        "saved_to": str(report_file),
        "summary": {
            "hosts": len(hosts),
            "findings": len(findings),
            "severity_breakdown": sev_counts,
            "risk_level": risk_level,
        },
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
