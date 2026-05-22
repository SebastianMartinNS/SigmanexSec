"""
mcp_servers/recon_server.py — MCP Server: Reconnaissance.

Wraps:  nmap, masscan, dnsrecon, dnsenum, whatweb, nikto,
        gobuster, ffuf, feroxbuster, dirb, wfuzz, dirsearch,
        wafw00f, enum4linux, nbtscan, snmp-check, onesixtyone.

Every tool is executed via ToolExecutor (scope checked, audited, timeout-guarded).
Output is returned as a structured dict so the LLM can reason about it.
"""
import json
import os
import re
import sys
from pathlib import Path

# nmap output is attacker-controlled (probed target). Use defusedxml so a
# malicious target cannot trigger entity-expansion or external-entity
# attacks against the recon MCP server process.
from defusedxml import ElementTree as ET

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv

load_dotenv()

from mcp.server.fastmcp import FastMCP

from core.audit_log import AuditLog
from core.executor import ToolExecutor
from core.models import Phase
from core.scope_validator import ScopeValidator
from core.session_store import SessionStore

# ── Singletons ───────────────────────────────────────────────────────────────
# v3.1 W1.4 — Bootstrap via BaseMCPServer. The DI container shares one
# ``AuditLog`` / ``SessionStore`` / ``ToolExecutor`` instance across every
# MCP server in the process so the BLAKE2b hash chain stays single-rooted
# (forensic integrity). Legacy env-var resolution preserved.
from mcp_servers.base import BaseMCPServer

_srv   = BaseMCPServer.from_env(name="recon")
store  = _srv.store
audit  = _srv.audit
_exe   = _srv.executor          # scope_validator set per call by callers
mcp    = _srv.mcp
from core.tool_output_store import get_tool_output_store  # noqa: E402  (kept for tests that import it)
from mcp_servers._response import _hard_cap_bytes  # noqa: F401  (re-exported)

_srv.install_default_handlers()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_error_snippet(text: str | None) -> str:
    """Return a bounded snippet of unparseable stdout.

    The legacy ``"raw": result.stdout`` pattern shipped up to ``executor.
    max_output_bytes`` (512 KB \u2248 125 K tokens) inline to the LLM whenever
    JSON parsing failed. That single field caused the 346 K token
    prompt-explosion observed on 2026-04-30. We now ship at most
    ``SAP_MCP_HARD_CAP_BYTES`` worth of stdout; the full payload remains
    addressable via ``output_ref`` + ``read_tool_output_recon``.
    """
    if not text:
        return ""
    cap = _hard_cap_bytes()
    if len(text) <= cap:
        return text
    # Head+tail split keeps the opening (often a CLI banner) and the end
    # (typical place for diagnostic / summary lines).
    head = text[: max(1024, cap - 1024)]
    tail = text[-1024:]
    return head + "\n... [truncated " + str(len(text) - len(head) - len(tail)) + " chars] ...\n" + tail


def _output_ref_dict(result) -> dict:
    """Extract the canonical ``output_ref`` block from an ExecutionResult."""
    ref = getattr(result, "output_ref", None)
    if ref is None:
        return {}
    return {
        "stdout_uri": getattr(ref, "stdout_uri", ""),
        "stderr_uri": getattr(ref, "stderr_uri", ""),
        "artifacts_uri": getattr(ref, "artifacts_uri", ""),
    }

async def _get_scope(engagement_id: str) -> ScopeValidator | None:
    await store.init()
    eng = await store.get_engagement(engagement_id)
    if not eng:
        return None
    return ScopeValidator(
        cidrs=eng.scope_cidrs,
        domains=eng.scope_domains,
        urls=eng.scope_urls,
        engagement_id=engagement_id,
    )


def _parse_nmap_xml(xml_output: str) -> dict:
    """Parse nmap -oX output into a structured dict."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return {"raw": xml_output}

    hosts = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        hostname_el = host_el.find(".//hostname")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        os_el = host_el.find(".//osmatch")
        os_guess = os_el.get("name", "") if os_el is not None else ""

        services = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            services.append({
                "port": int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "service": svc_el.get("name", "") if svc_el is not None else "",
                "version": (
                    f"{svc_el.get('product','')} {svc_el.get('version','')}".strip()
                    if svc_el is not None else ""
                ),
                "banner": svc_el.get("extrainfo", "") if svc_el is not None else "",
            })

        script_output = []
        for script_el in host_el.findall(".//script"):
            script_output.append({
                "id": script_el.get("id", ""),
                "output": script_el.get("output", ""),
            })

        hosts.append({
            "ip": ip,
            "hostname": hostname,
            "os_guess": os_guess,
            "services": services,
            "scripts": script_output,
        })

    return {"hosts": hosts, "host_count": len(hosts)}


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def nmap_scan(
    engagement_id: str,
    target: str,
    ports: str = "top1000",
    scan_type: str = "syn",
    service_detection: bool = True,
    os_detection: bool = False,
    scripts: str = "",
    timing: int = 3,
) -> dict:
    """
    Run an Nmap scan against an authorized target.

    Args:
        engagement_id: Active engagement ID (scope is checked automatically)
        target: IP, CIDR, or hostname — MUST be in engagement scope
        ports: Port specification: "top1000", "all", or "80,443,8080" or "1-1024"
        scan_type: syn (default), tcp, udp, comprehensive
        service_detection: Enable -sV (service/version detection)
        os_detection: Enable -O (requires root)
        scripts: NSE scripts e.g. "vuln", "smb-enum-shares", "http-headers"
        timing: Nmap timing template 0-5 (default 3)
    Returns:
        Structured dict with hosts, open ports, services, script output.
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    args = []

    # Scan type
    scan_map = {"syn": "-sS", "tcp": "-sT", "udp": "-sU", "comprehensive": "-sS -sU"}
    args.extend(scan_map.get(scan_type, "-sS").split())

    # Ports
    if ports == "top1000":
        args += ["--top-ports", "1000"]
    elif ports == "all":
        args += ["-p-"]
    else:
        args += ["-p", ports]

    if service_detection:
        args.append("-sV")
    if os_detection:
        args.append("-O")
    if scripts:
        args += ["--script", scripts]

    args += [f"-T{timing}"]
    args += ["-oX", "-"]   # XML to stdout for structured parsing
    args.append(target)

    result = await _exe.run(
        "nmap", args,
        engagement_id=engagement_id,
        phase=Phase.SCANNING,
        target=target,
        timeout=600,
    )

    if result.returncode != 0 and not result.stdout.strip():
        return {"error": result.stderr, "command": result.command}

    parsed = _parse_nmap_xml(result.stdout)
    parsed["command"] = result.command
    parsed["duration_seconds"] = result.duration_seconds
    return parsed


@mcp.tool()
async def masscan_scan(
    engagement_id: str,
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
) -> dict:
    """
    High-speed port scan with Masscan. Useful for discovering open ports
    across large CIDR ranges quickly before a detailed nmap scan.

    Args:
        rate: Packets per second (default 1000, max recommend 10000 on LAN)
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    result = await _exe.run(
        "masscan",
        [target, "-p", ports, "--rate", str(rate), "--output-format", "list"],
        engagement_id=engagement_id,
        phase=Phase.SCANNING,
        target=target,
        timeout=300,
    )

    # Parse masscan list format: "open tcp 80 10.0.0.1 ..."
    open_ports = []
    for line in result.stdout.splitlines():
        if line.startswith("open"):
            parts = line.split()
            if len(parts) >= 4:
                open_ports.append({
                    "state": parts[0],
                    "protocol": parts[1],
                    "port": int(parts[2]),
                    "ip": parts[3],
                })

    return {
        "open_ports": open_ports,
        "count": len(open_ports),
        "command": result.command,
        "duration_seconds": result.duration_seconds,
    }


@mcp.tool()
async def dns_recon(
    engagement_id: str,
    domain: str,
    mode: str = "standard",
    wordlist: str = "",
) -> dict:
    """
    DNS enumeration using dnsrecon.

    Args:
        mode: standard (A,MX,NS,SOA), zonexfer (attempt zone transfer),
              bruteforce (subdomain brute force), reverse (reverse lookup on CIDR)
        wordlist: Path to wordlist for bruteforce mode (optional, uses built-in if empty)
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    args = ["-d", domain, "-j", "/dev/stdout"]

    if mode == "zonexfer":
        args += ["-t", "axfr"]
    elif mode == "bruteforce":
        args += ["-t", "brt"]
        if wordlist:
            args += ["-D", wordlist]
    elif mode == "reverse":
        args += ["-t", "rvl"]
    else:
        args += ["-t", "std"]

    result = await _exe.run(
        "dnsrecon", args,
        engagement_id=engagement_id,
        phase=Phase.RECON,
        target=domain,
        timeout=120,
    )

    # Try to parse JSON output; fall back to raw
    try:
        # dnsrecon -j outputs JSON after a log prefix
        json_match = re.search(r"(\[{.*}\])", result.stdout, re.DOTALL)
        if json_match:
            records = json.loads(json_match.group(1))
        else:
            records = json.loads(result.stdout)
    except Exception:
        records = []

    return {
        "domain": domain,
        "mode": mode,
        "records": records,
        "raw": _parse_error_snippet(result.stdout) if not records else "",
        "duration_seconds": result.duration_seconds,
        "call_id": result.call_id,
        "output_ref": _output_ref_dict(result),
        "full_size_bytes": {
            "stdout": result.stdout_bytes_full,
            "stderr": result.stderr_bytes_full,
        },
    }


@mcp.tool()
async def web_fingerprint(
    engagement_id: str,
    url: str,
    aggressive: bool = False,
) -> dict:
    """
    Identify web technologies, CMS, server software using WhatWeb.

    Returns detected technologies with confidence levels.
    Useful before deciding which exploits / scanners to run.
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    args = [url, "--log-json=-"]
    if aggressive:
        args.append("-a3")
    else:
        args.append("-a1")

    result = await _exe.run(
        "whatweb", args,
        engagement_id=engagement_id,
        phase=Phase.RECON,
        target=url,
        timeout=60,
    )

    try:
        data = json.loads(result.stdout)
    except Exception:
        data = []

    return {
        "url": url,
        "technologies": data,
        "raw": _parse_error_snippet(result.stdout) if not data else "",
        "duration_seconds": result.duration_seconds,
        "call_id": result.call_id,
        "output_ref": _output_ref_dict(result),
        "full_size_bytes": {
            "stdout": result.stdout_bytes_full,
            "stderr": result.stderr_bytes_full,
        },
    }


@mcp.tool()
async def waf_detect(
    engagement_id: str,
    url: str,
) -> dict:
    """
    Detect the presence and type of Web Application Firewall (WAF) using wafw00f.
    Important before fuzzing/exploitation to adjust techniques.
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    result = await _exe.run(
        "wafw00f", [url, "-o", "-", "-f", "json"],
        engagement_id=engagement_id,
        phase=Phase.RECON,
        target=url,
        timeout=30,
    )

    try:
        data = json.loads(result.stdout)
    except Exception:
        data = {"raw": _parse_error_snippet(result.stdout)}

    return {
        "url": url,
        "waf_info": data,
        "duration_seconds": result.duration_seconds,
        "call_id": result.call_id,
        "output_ref": _output_ref_dict(result),
        "full_size_bytes": {
            "stdout": result.stdout_bytes_full,
            "stderr": result.stderr_bytes_full,
        },
    }


@mcp.tool()
async def web_vuln_scan(
    engagement_id: str,
    url: str,
    tuning: str = "",
    proxy: str = "",
) -> dict:
    """
    Automated web vulnerability scan using Nikto.
    Detects outdated software, dangerous files, CGI vulnerabilities,
    server misconfigurations, and common web issues.

    Args:
        tuning: Nikto tuning string (e.g. "1" for interesting files,
                "6" for Denial of Service checks — use with caution)
        proxy: Optional HTTP proxy e.g. "http://127.0.0.1:8080"
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    args = ["-h", url, "-o", "-", "-Format", "json", "-nointeractive"]
    if tuning:
        args += ["-Tuning", tuning]
    if proxy:
        args += ["-useproxy", proxy]

    result = await _exe.run(
        "nikto", args,
        engagement_id=engagement_id,
        phase=Phase.SCANNING,
        target=url,
        timeout=300,
    )

    try:
        data = json.loads(result.stdout)
    except Exception:
        data = {"raw": _parse_error_snippet(result.stdout)}

    return {
        "url": url,
        "scan_results": data,
        "duration_seconds": result.duration_seconds,
        "call_id": result.call_id,
        "output_ref": _output_ref_dict(result),
        "full_size_bytes": {
            "stdout": result.stdout_bytes_full,
            "stderr": result.stderr_bytes_full,
        },
    }


@mcp.tool()
async def dir_fuzz(
    engagement_id: str,
    url: str,
    wordlist: str = "common",
    extensions: str = "",
    threads: int = 40,
    recursive: bool = False,
    tool: str = "ffuf",
    status_codes: str = "200,204,301,302,307,401,403",
) -> dict:
    """
    Directory and file fuzzing on web applications.

    Args:
        wordlist: "common", "big", "api", "seclists-discovery", or absolute path
        extensions: Comma-separated e.g. "php,asp,html,txt"
        threads: Concurrent requests (default 40)
        recursive: Recursively fuzz discovered directories (feroxbuster only)
        tool: ffuf (default), gobuster, feroxbuster, dirsearch
        status_codes: Filter responses by status code
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    # Resolve wordlist path
    wordlist_paths = {
        "common":            "/usr/share/wordlists/dirb/common.txt",
        "big":               "/usr/share/wordlists/dirb/big.txt",
        "api":               "/usr/share/wordlists/seclists/Discovery/Web-Content/api/objects.txt",
        "seclists-discovery":"/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    }
    wl = wordlist_paths.get(wordlist, wordlist)

    ext_flag = extensions if extensions else ""

    if tool == "ffuf":
        args = ["-u", f"{url}/FUZZ", "-w", wl, "-t", str(threads),
                "-mc", status_codes, "-o", "/dev/stdout", "-of", "json"]
        if ext_flag:
            args += ["-e", ext_flag if ext_flag.startswith(".") else f".{ext_flag}"]

    elif tool == "gobuster":
        args = ["dir", "-u", url, "-w", wl, "-t", str(threads),
                "-s", status_codes, "--no-error"]
        if ext_flag:
            args += ["-x", ext_flag]

    elif tool == "feroxbuster":
        args = ["--url", url, "--wordlist", wl, "--threads", str(threads),
                "--status-codes", status_codes, "--json", "--output", "/dev/stdout",
                "--no-state"]
        if ext_flag:
            args += ["--extensions", ext_flag]
        if recursive:
            args.append("--recurse")
        else:
            args += ["--depth", "1"]

    elif tool == "dirsearch":
        args = ["-u", url, "-w", wl, "-t", str(threads),
                "--format", "json", "-o", "/dev/stdout"]
        if ext_flag:
            args += ["-e", ext_flag]
    else:
        return {"error": f"Unknown tool '{tool}'. Use ffuf/gobuster/feroxbuster/dirsearch"}

    result = await _exe.run(
        tool, args,
        engagement_id=engagement_id,
        phase=Phase.SCANNING,
        target=url,
        timeout=600,
    )

    try:
        data = json.loads(result.stdout)
    except Exception:
        # Parse line-by-line for gobuster / dirsearch plain output
        found = []
        for line in result.stdout.splitlines():
            if "Status:" in line or "[200" in line or "[301" in line or "[403" in line:
                found.append(line.strip())
        data = {"results": found}

    return {
        "url": url,
        "tool": tool,
        "wordlist": wl,
        "results": data,
        "duration_seconds": result.duration_seconds,
    }


@mcp.tool()
async def smb_enum(
    engagement_id: str,
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
) -> dict:
    """
    SMB/NetBIOS enumeration: shares, users, groups, policies, OS info.
    Uses enum4linux-ng (or enum4linux as fallback).

    Critical for mapping Windows / Active Directory environments.
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    args = ["-a", "-o"]
    if username:
        args += ["-u", username]
    if password:
        args += ["-p", password]
    if domain:
        args += ["-d", domain]
    args.append(target)

    result = await _exe.run(
        "enum4linux", args,
        engagement_id=engagement_id,
        phase=Phase.RECON,
        target=target,
        timeout=120,
    )
    return {
        "target": target,
        "output": result.stdout,
        "stderr": result.stderr,
        "duration_seconds": result.duration_seconds,
    }


@mcp.tool()
async def snmp_enum(
    engagement_id: str,
    target: str,
    community: str = "public",
    version: str = "2c",
) -> dict:
    """
    SNMP enumeration: system info, interfaces, routing table, users.
    Runs snmp-check.
    """
    scope = await _get_scope(engagement_id)
    _exe._scope = scope

    result = await _exe.run(
        "snmp-check",
        [target, "-c", community, f"-v{version}"],
        engagement_id=engagement_id,
        phase=Phase.RECON,
        target=target,
        timeout=60,
    )
    return {
        "target": target,
        "community": community,
        "output": result.stdout,
        "duration_seconds": result.duration_seconds,
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
