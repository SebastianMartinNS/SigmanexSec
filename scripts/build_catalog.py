#!/usr/bin/env python3
"""
scripts/build_catalog.py — Generate parrot_tools.yaml from a structured
Python source-of-truth.

Why a generator? With ~150 entries × rich docs (when/why/how/refs/risk/
interactive/examples) the catalogue is several thousand lines long. Hand-
editing that YAML reliably is error-prone; a typed Python list keeps the
schema homogeneous, makes audits trivial (grep on Python syntax), and
lets us regenerate the file deterministically as new tools are added.

Run:  python3 scripts/build_catalog.py

Output: parrot_tools.yaml  (overwrites in place; previous file backed up
to parrot_tools.yaml.bak).
"""
from __future__ import annotations

import shutil
from pathlib import Path
from textwrap import dedent

import yaml

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "parrot_tools.yaml"
BAK = REPO / "parrot_tools.yaml.bak"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def t(
    name, binary, category, description, *,
    sudo=False, sudo_reason="",
    timeout=300,
    mitre=None,
    risk="medium",
    interactive=False, interaction=None,
    when="", why="", how="", refs=None,
    args_schema=None, argv=None,
    scope_arg=None, parser="raw",
    examples=None, output_artifacts=None,
    safe_dry_run_args=None,
    pii=False,
    install_via="",
    requires_manual_setup=False,
):
    """Build one descriptor dict (with sensible defaults).

    ``pii`` (Phase 8 — person-OSINT): when True the tool deals with
    personal data; the executor flags audit entries with ``pii=true``.
    ``scope_arg`` may be ``email|username|person|social_handle`` for
    identity-targeting tools.
    """
    d = {
        "name": name,
        "binary": binary,
        "category": category,
        "description": description,
        "requires_sudo": bool(sudo),
        "default_timeout_seconds": int(timeout),
        "mitre": mitre or [],
        "risk_level": risk,
        "interactive": bool(interactive),
        "args_schema": args_schema or {"type": "object", "properties": {}, "required": []},
        "argv_template": argv or [],
        "scope_arg": scope_arg,
        "parser": parser,
    }
    if sudo_reason:
        d["sudo_reason"] = sudo_reason
    if when:
        d["when"] = dedent(when).strip()
    if why:
        d["why"] = dedent(why).strip()
    if how:
        d["how_notes"] = dedent(how).strip()
    if refs:
        d["references"] = list(refs)
    if interaction:
        d["interaction"] = interaction
    if examples:
        d["examples"] = examples
    if output_artifacts:
        d["output_artifacts"] = list(output_artifacts)
    if safe_dry_run_args:
        d["safe_dry_run_args"] = safe_dry_run_args
    if pii:
        d["pii"] = True
    if install_via:
        d["install_via"] = install_via
    if requires_manual_setup:
        d["requires_manual_setup"] = True
    return d


def S(props, required=None):
    """Shortcut for args_schema."""
    return {"type": "object", "properties": props, "required": required or []}


P_str = lambda **kw: {"type": "string", **kw}
P_int = lambda **kw: {"type": "integer", **kw}
P_bool = lambda **kw: {"type": "boolean", **kw}
P_enum = lambda values, **kw: {"type": "string", "enum": values, **kw}


# Common interaction protocols
PTY_GENERIC = {
    "type": "pty",
    "prompts": [r"[#$>] $"],
    "commands_help": "Send shell-style commands; close the session when done.",
}
PTY_MSF = {
    "type": "pty",
    "prompts": [r"msf6? .*> $", r"meterpreter > $"],
    "commands_help": "Standard Metasploit console: use, set, run, exploit, sessions -i N, exit.",
}
PTY_EVILWINRM = {
    "type": "pty",
    "prompts": [r"\*Evil-WinRM\* PS .*> $"],
    "commands_help": "PowerShell prompt; type 'menu' for evil-winrm helpers, 'exit' to quit.",
}
PTY_SQLMAP = {
    "type": "pty",
    "prompts": [r"\[\d+ INF\] ", r"do you want to "],
    "commands_help": "Answer interactive prompts (Y/N/q). sqlmap will pause for confirmation on risky payloads.",
}
PTY_MITMPROXY = {
    "type": "pty",
    "prompts": [r"\[\d+:\d+:\d+\] "],
    "commands_help": "Press '?' for help inside mitmproxy; commands include 'q' to quit, 'i' to intercept.",
}


# ─────────────────────────────────────────────────────────────────────────────
# Catalog data
# ─────────────────────────────────────────────────────────────────────────────

TOOLS: list[dict] = []
add = TOOLS.append


# ─── RECON / OSINT ────────────────────────────────────────────────────────
add(t("amass_enum", "amass", "recon",
      "Subdomain enumeration via OWASP Amass (passive sources).",
      timeout=900, mitre=["T1590.002"], risk="low",
      when="You need a deep, multi-source passive subdomain map of a target apex domain.",
      why="Amass aggregates ~80 OSINT sources and certificate transparency logs in a single run.",
      how="Pure passive (`-passive`) is OPSEC-safe; active mode performs DNS bruteforce — only with explicit authorization.",
      refs=["https://github.com/owasp-amass/amass"],
      args_schema=S({
          "domain":  P_str(),
          "passive": P_bool(default=True),
          "timeout": P_int(default=10, description="minutes"),
      }, ["domain"]),
      argv=["enum", "{{?passive}}-passive{{/passive}}", "-d", "{{domain}}",
            "{{?timeout}}-timeout{{/timeout}}", "{{?timeout}}{{timeout}}{{/timeout}}"],
      scope_arg="domain",
      examples=[{"domain": "example.com"}]))

add(t("subfinder_run", "subfinder", "recon",
      "Fast passive subdomain discovery (ProjectDiscovery).",
      timeout=600, mitre=["T1590.002"], risk="low",
      when="Quick first pass when you only need passive results in <1 minute.",
      why="Lighter and faster than amass; fewer sources but excellent default coverage.",
      refs=["https://github.com/projectdiscovery/subfinder"],
      args_schema=S({"domain": P_str(), "silent": P_bool(default=True)}, ["domain"]),
      argv=["-d", "{{domain}}", "{{?silent}}-silent{{/silent}}"],
      scope_arg="domain", examples=[{"domain": "example.com"}]))

add(t("assetfinder_run", "assetfinder", "recon",
      "Find related domains/subdomains using public sources.",
      timeout=300, mitre=["T1590.002"], risk="low",
      when="Cheap secondary source to feed amass/subfinder results into a dedup pipeline.",
      why="Tiny Go binary, zero dependencies, fast.",
      refs=["https://github.com/tomnomnom/assetfinder"],
      args_schema=S({"domain": P_str(), "subs_only": P_bool(default=True)}, ["domain"]),
      argv=["{{?subs_only}}--subs-only{{/subs_only}}", "{{domain}}"],
      scope_arg="domain"))

add(t("findomain_run", "findomain", "recon",
      "Cross-platform passive subdomain enumeration.",
      timeout=300, mitre=["T1590.002"], risk="low",
      when="Alternative source when amass/subfinder yield few results.",
      refs=["https://github.com/findomain/findomain"],
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["-t", "{{domain}}", "-q"], scope_arg="domain"))

add(t("dnsx_resolve", "dnsx", "recon",
      "High-performance DNS resolver / wildcard checker.",
      timeout=300, mitre=["T1590.002"], risk="low",
      when="You have a large list of subdomain candidates and need to resolve & filter alive ones quickly.",
      why="Goroutine-based, supports A/AAAA/CNAME/NS/PTR, wildcard detection.",
      refs=["https://github.com/projectdiscovery/dnsx"],
      args_schema=S({
          "input_list": P_str(description="path to file with one host per line"),
          "record":     P_enum(["a", "aaaa", "cname", "ns", "ptr", "mx"], default="a"),
      }, ["input_list"]),
      argv=["-l", "{{input_list}}", "-{{record}}", "-silent"],
      scope_arg=None))

add(t("dnsrecon_run", "dnsrecon", "recon",
      "DNS enumeration: A/AAAA/MX/NS/SRV/zone-transfer/bruteforce.",
      timeout=600, mitre=["T1590.002"], risk="low",
      when="You need a single tool that enumerates record types, attempts AXFR, and does bruteforce.",
      refs=["https://github.com/darkoperator/dnsrecon"],
      args_schema=S({
          "domain": P_str(),
          "type":   P_enum(["std", "axfr", "brt", "rvl"], default="std"),
          "wordlist": P_str(default="/usr/share/dnsrecon/namelist.txt"),
      }, ["domain"]),
      argv=["-d", "{{domain}}", "-t", "{{type}}",
            "{{?wordlist}}-D{{/wordlist}}", "{{?wordlist}}{{wordlist}}{{/wordlist}}"],
      scope_arg="domain"))

add(t("dnsenum_run", "dnsenum", "recon",
      "DNS enumeration with reverse lookups and Google scraping.",
      timeout=600, mitre=["T1590.002"], risk="low",
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["{{domain}}"], scope_arg="domain"))

add(t("fierce_run", "fierce", "recon",
      "DNS reconnaissance: zone transfer + close-IP enumeration.",
      timeout=600, mitre=["T1590.002"], risk="low",
      when="Looking for misconfigured zone transfers and adjacent IP ranges.",
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["--domain", "{{domain}}"], scope_arg="domain"))

add(t("massdns_resolve", "massdns", "recon",
      "Mass DNS resolver — millions of names per minute.",
      timeout=900, mitre=["T1590.002"], risk="low",
      how="Requires a healthy resolver list; default Cloudflare/Quad9 list shipped with package.",
      refs=["https://github.com/blechschmidt/massdns"],
      args_schema=S({
          "input_list": P_str(),
          "resolvers":  P_str(default="/usr/share/massdns/lists/resolvers.txt"),
          "record":     P_enum(["A", "AAAA", "CNAME"], default="A"),
      }, ["input_list"]),
      argv=["-r", "{{resolvers}}", "-t", "{{record}}", "-o", "S", "{{input_list}}"]))

add(t("httpx_probe", "httpx", "recon",
      "Probe HTTP/HTTPS hosts for status, title, tech, TLS info.",
      timeout=600, mitre=["T1595.002"], risk="low",
      when="You have a list of hosts/subdomains and need to know which speak HTTP and what they serve.",
      why="Concurrent probes, JSON output, integrates with the rest of ProjectDiscovery suite.",
      refs=["https://github.com/projectdiscovery/httpx"],
      args_schema=S({
          "input_list":   P_str(description="file with hosts (one per line)"),
          "single_target": P_str(description="probe a single URL/host instead"),
          "status_code":  P_bool(default=True),
          "title":        P_bool(default=True),
          "tech_detect":  P_bool(default=True),
          "follow_redirects": P_bool(default=True),
      }),
      argv=["{{?input_list}}-l{{/input_list}}", "{{?input_list}}{{input_list}}{{/input_list}}",
            "{{?single_target}}-u{{/single_target}}", "{{?single_target}}{{single_target}}{{/single_target}}",
            "{{?status_code}}-status-code{{/status_code}}",
            "{{?title}}-title{{/title}}",
            "{{?tech_detect}}-tech-detect{{/tech_detect}}",
            "{{?follow_redirects}}-fr{{/follow_redirects}}",
            "-json", "-silent"],
      scope_arg="single_target", parser="jsonl"))

add(t("naabu_scan", "naabu", "recon",
      "Fast SYN/CONNECT port scanner (Go).",
      timeout=600, mitre=["T1046"], risk="medium",
      sudo=True, sudo_reason="SYN scan requires CAP_NET_RAW",
      when="Quick TCP top-N port sweep across many hosts.",
      refs=["https://github.com/projectdiscovery/naabu"],
      args_schema=S({
          "target": P_str(),
          "ports":  P_str(default="top-100"),
          "rate":   P_int(default=1000),
      }, ["target"]),
      argv=["-host", "{{target}}", "-p", "{{ports}}", "-rate", "{{rate}}",
            "-silent"], scope_arg="target"))

add(t("katana_crawl", "katana", "recon",
      "Headless web crawler with JS parsing.",
      timeout=900, mitre=["T1595.002"], risk="low",
      when="Map a web app's URL surface (forms, JS endpoints) before fuzzing.",
      refs=["https://github.com/projectdiscovery/katana"],
      args_schema=S({
          "url":   P_str(),
          "depth": P_int(default=3),
          "headless": P_bool(default=False),
      }, ["url"]),
      argv=["-u", "{{url}}", "-d", "{{depth}}",
            "{{?headless}}-headless{{/headless}}", "-silent"],
      scope_arg="url"))

add(t("waybackurls_run", "waybackurls", "recon",
      "Pull URLs for a domain from the Wayback Machine.",
      timeout=300, mitre=["T1593.003"], risk="low",
      when="OSINT for legacy endpoints / deleted pages still in archive.",
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["{{domain}}"], scope_arg="domain"))

add(t("gau_run", "gau", "recon",
      "Get All URLs from AlienVault OTX, Wayback, Common Crawl, URLScan.",
      timeout=300, mitre=["T1593.003"], risk="low",
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["{{domain}}"], scope_arg="domain"))

add(t("theharvester_run", "theHarvester", "recon",
      "OSINT: emails, subdomains, hosts from public sources.",
      timeout=900, mitre=["T1589.002"], risk="low",
      when="Open-source intelligence on people/emails for an org.",
      refs=["https://github.com/laramies/theHarvester"],
      args_schema=S({
          "domain":  P_str(),
          "limit":   P_int(default=500),
          "sources": P_str(default="all"),
      }, ["domain"]),
      argv=["-d", "{{domain}}", "-l", "{{limit}}", "-b", "{{sources}}"],
      scope_arg="domain"))

add(t("whois_lookup", "whois", "recon",
      "WHOIS registration data lookup.",
      timeout=60, risk="low",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["{{target}}"], scope_arg="target"))

add(t("dig_query", "dig", "recon",
      "DNS query tool (BIND).",
      timeout=60, risk="low",
      args_schema=S({
          "name":   P_str(),
          "record": P_enum(["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "ANY"], default="A"),
          "server": P_str(default=""),
      }, ["name"]),
      argv=["{{?server}}@{{server}}{{/server}}", "{{name}}", "{{record}}", "+short"],
      scope_arg="name"))

add(t("host_lookup", "host", "recon",
      "Simple DNS lookup utility.",
      timeout=30, risk="low",
      args_schema=S({"name": P_str()}, ["name"]),
      argv=["{{name}}"], scope_arg="name"))

add(t("nslookup_query", "nslookup", "recon",
      "Interactive DNS query.",
      timeout=60, risk="low",
      args_schema=S({"name": P_str(), "server": P_str(default="")}, ["name"]),
      argv=["{{name}}", "{{?server}}{{server}}{{/server}}"],
      scope_arg="name"))

add(t("masscan_scan", "masscan", "recon",
      "Internet-scale port scanner.",
      timeout=1800, mitre=["T1046"], risk="high",
      sudo=True, sudo_reason="SYN scan requires raw sockets",
      when="You need to scan large CIDR ranges quickly (millions of pps).",
      how="ALWAYS rate-limit (`--rate`) on shared networks. Default kernel buffer can drop packets at >100kpps.",
      refs=["https://github.com/robertdavidgraham/masscan"],
      args_schema=S({
          "target": P_str(),
          "ports":  P_str(default="0-65535"),
          "rate":   P_int(default=1000),
      }, ["target"]),
      argv=["-p", "{{ports}}", "{{target}}", "--rate", "{{rate}}", "-oG", "-"],
      scope_arg="target"))

add(t("rustscan_run", "rustscan", "recon",
      "Modern TCP port scanner that pipes results to nmap.",
      timeout=900, mitre=["T1046"], risk="medium",
      args_schema=S({
          "target": P_str(),
          "ports":  P_str(default=""),
          "ulimit": P_int(default=5000),
      }, ["target"]),
      argv=["-a", "{{target}}", "{{?ports}}-p{{/ports}}", "{{?ports}}{{ports}}{{/ports}}",
            "--ulimit", "{{ulimit}}", "--no-banner"], scope_arg="target"))

add(t("nbtscan_run", "nbtscan", "recon",
      "Scan NetBIOS name servers on local or remote network.",
      timeout=300, mitre=["T1018"], risk="low",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["{{target}}"], scope_arg="target"))

add(t("netdiscover_run", "netdiscover", "recon",
      "Active/passive ARP reconnaissance.",
      timeout=120, mitre=["T1018"], risk="medium",
      sudo=True, sudo_reason="ARP requires raw socket",
      args_schema=S({"interface": P_str(), "range": P_str()}, ["interface"]),
      argv=["-i", "{{interface}}", "{{?range}}-r{{/range}}", "{{?range}}{{range}}{{/range}}",
            "-P"]))

add(t("arp_scan_run", "arp-scan", "recon",
      "Layer-2 host discovery on local network.",
      timeout=120, mitre=["T1018"], risk="medium",
      sudo=True, sudo_reason="ARP raw socket",
      args_schema=S({
          "interface": P_str(),
          "range":     P_str(default="--localnet"),
      }, ["interface"]),
      argv=["-I", "{{interface}}", "{{range}}"]))

add(t("snmpwalk_query", "snmpwalk", "recon",
      "SNMP tree walk via GETNEXT.",
      timeout=300, mitre=["T1046"], risk="low",
      args_schema=S({
          "target":    P_str(),
          "community": P_str(default="public"),
          "version":   P_enum(["1", "2c", "3"], default="2c"),
          "oid":       P_str(default=""),
      }, ["target"]),
      argv=["-v", "{{version}}", "-c", "{{community}}", "{{target}}",
            "{{?oid}}{{oid}}{{/oid}}"], scope_arg="target"))

add(t("onesixtyone_run", "onesixtyone", "recon",
      "Fast SNMP community string scanner.",
      timeout=300, mitre=["T1110.001"], risk="medium",
      args_schema=S({
          "target":    P_str(),
          "community_file": P_str(default="/usr/share/wordlists/onesixtyone/community.txt"),
      }, ["target"]),
      argv=["-c", "{{community_file}}", "{{target}}"], scope_arg="target"))


# ─── WEB ──────────────────────────────────────────────────────────────────
add(t("ffuf_fuzz", "ffuf", "web",
      "Web fuzzer: paths, parameters, vhosts, subdomains.",
      timeout=900, mitre=["T1595.003"], risk="low",
      when="Directory/file/parameter discovery on a web app you own.",
      why="Fastest mainstream fuzzer; pluggable matcher/filter, recursion, JSON output.",
      refs=["https://github.com/ffuf/ffuf"],
      args_schema=S({
          "url":      P_str(description="must contain FUZZ marker"),
          "wordlist": P_str(default="/usr/share/wordlists/dirb/common.txt"),
          "match_codes": P_str(default="200,204,301,302,307,401,403"),
          "extensions":  P_str(default=""),
          "threads":     P_int(default=40),
      }, ["url"]),
      argv=["-u", "{{url}}", "-w", "{{wordlist}}",
            "-mc", "{{match_codes}}",
            "{{?extensions}}-e{{/extensions}}", "{{?extensions}}{{extensions}}{{/extensions}}",
            "-t", "{{threads}}", "-of", "json", "-o", "/tmp/ffuf-out.json"],
      scope_arg="url",
      output_artifacts=["/tmp/ffuf-out.json"]))

add(t("gobuster_dir", "gobuster", "web",
      "Directory/DNS/vhost brute-forcer.",
      timeout=900, mitre=["T1595.003"], risk="low",
      args_schema=S({
          "mode":     P_enum(["dir", "dns", "vhost"], default="dir"),
          "url":      P_str(),
          "wordlist": P_str(default="/usr/share/wordlists/dirb/common.txt"),
          "threads":  P_int(default=20),
      }, ["url"]),
      argv=["{{mode}}", "-u", "{{url}}", "-w", "{{wordlist}}",
            "-t", "{{threads}}", "-q"], scope_arg="url"))

add(t("feroxbuster_run", "feroxbuster", "web",
      "Recursive content discovery written in Rust.",
      timeout=900, mitre=["T1595.003"], risk="low",
      args_schema=S({
          "url": P_str(),
          "wordlist": P_str(default="/usr/share/wordlists/dirb/common.txt"),
          "depth":    P_int(default=4),
      }, ["url"]),
      argv=["-u", "{{url}}", "-w", "{{wordlist}}", "-d", "{{depth}}", "-q"],
      scope_arg="url"))

add(t("dirsearch_run", "dirsearch", "web",
      "Web path scanner with smart wordlists.",
      timeout=900, mitre=["T1595.003"], risk="low",
      args_schema=S({
          "url": P_str(),
          "extensions": P_str(default="php,html,js,txt"),
      }, ["url"]),
      argv=["-u", "{{url}}", "-e", "{{extensions}}", "--quiet-mode"],
      scope_arg="url"))

add(t("nuclei_scan", "nuclei", "vuln",
      "Template-based vulnerability scanner.",
      timeout=1200, mitre=["T1595.002"], risk="medium",
      when="You need broad-spectrum CVE/exposure/misconfig checks across one or many web targets.",
      why="Battle-tested templates curated by ProjectDiscovery; YAML-defined, easy to extend.",
      how="Tag-filter (`-tags cve,exposure`) to keep runs short; templates auto-update via `nuclei -update-templates`.",
      refs=["https://nuclei.projectdiscovery.io/"],
      args_schema=S({
          "target":   P_str(),
          "severity": P_enum(["info", "low", "medium", "high", "critical"]),
          "templates": P_str(description="e.g. cves/2024/, exposures/"),
          "rate_limit": P_int(default=150),
      }, ["target"]),
      argv=["-target", "{{target}}",
            "{{?severity}}-severity{{/severity}}", "{{?severity}}{{severity}}{{/severity}}",
            "{{?templates}}-t{{/templates}}", "{{?templates}}{{templates}}{{/templates}}",
            "-rl", "{{rate_limit}}", "-jsonl", "-silent"],
      scope_arg="target", parser="jsonl"))

add(t("nikto_scan", "nikto", "vuln",
      "Web server scanner: outdated versions, dangerous files, misconfig.",
      timeout=1200, mitre=["T1595.002"], risk="medium",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["-h", "{{url}}", "-Format", "json", "-o", "/tmp/nikto.json"],
      scope_arg="url", parser="raw",
      output_artifacts=["/tmp/nikto.json"]))

add(t("wpscan_run", "wpscan", "vuln",
      "WordPress vulnerability scanner.",
      timeout=900, mitre=["T1190"], risk="medium",
      args_schema=S({
          "url":   P_str(),
          "enumerate": P_str(default="vp,vt,u", description="vp=plugins, vt=themes, u=users"),
          "api_token": P_str(default=""),
      }, ["url"]),
      argv=["--url", "{{url}}", "-e", "{{enumerate}}",
            "{{?api_token}}--api-token{{/api_token}}", "{{?api_token}}{{api_token}}{{/api_token}}",
            "--no-banner", "--format", "json"],
      scope_arg="url", parser="jsonl"))

add(t("whatweb_id", "whatweb", "web",
      "Web technology identifier.",
      timeout=300, mitre=["T1592.002"], risk="low",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["{{url}}", "--log-json=-", "-q"],
      scope_arg="url", parser="jsonl"))

add(t("wafw00f_detect", "wafw00f", "web",
      "Identify and fingerprint Web Application Firewalls.",
      timeout=120, risk="low",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["{{url}}"], scope_arg="url"))

add(t("dalfox_xss", "dalfox", "web",
      "Parameter analysis & XSS scanning.",
      timeout=900, mitre=["T1059.007"], risk="medium",
      args_schema=S({
          "url": P_str(),
          "method": P_enum(["GET", "POST"], default="GET"),
      }, ["url"]),
      argv=["url", "{{url}}", "-X", "{{method}}", "--silent"], scope_arg="url"))

add(t("xsstrike_run", "xsstrike", "web",
      "Advanced XSS detection suite.",
      timeout=900, mitre=["T1059.007"], risk="medium",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["-u", "{{url}}"], scope_arg="url"))

add(t("commix_run", "commix", "web",
      "Automated OS command-injection exploitation.",
      timeout=1200, mitre=["T1059"], risk="high",
      args_schema=S({
          "url":    P_str(),
          "data":   P_str(default=""),
          "level":  P_int(default=1),
      }, ["url"]),
      argv=["--url", "{{url}}",
            "{{?data}}--data{{/data}}", "{{?data}}{{data}}{{/data}}",
            "--level", "{{level}}", "--batch"],
      scope_arg="url"))

add(t("sqlmap_run", "sqlmap", "web",
      "Automatic SQL injection and database takeover (one-shot).",
      timeout=1800, mitre=["T1190"], risk="high",
      when="A specific URL/parameter is suspected of SQLi and you want a non-interactive sweep.",
      how="`--batch` accepts default for all prompts; for interactive mode use parrot_session_start instead.",
      refs=["http://sqlmap.org/"],
      args_schema=S({
          "url": P_str(),
          "level": P_int(default=1),
          "risk":  P_int(default=1),
          "data":  P_str(default=""),
          "dbs":   P_bool(default=False),
      }, ["url"]),
      argv=["-u", "{{url}}", "--level", "{{level}}", "--risk", "{{risk}}",
            "{{?data}}--data{{/data}}", "{{?data}}{{data}}{{/data}}",
            "{{?dbs}}--dbs{{/dbs}}", "--batch"], scope_arg="url"))

add(t("sqlmap_interactive", "sqlmap", "web",
      "Interactive sqlmap session (prompts for risky payloads).",
      timeout=3600, mitre=["T1190"], risk="high",
      interactive=True, interaction=PTY_SQLMAP,
      when="You need to confirm/decline individual payloads instead of `--batch`.",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["-u", "{{url}}"], scope_arg="url"))

add(t("zaproxy_baseline", "zaproxy", "vuln",
      "OWASP ZAP baseline scan (headless).",
      timeout=1800, mitre=["T1595.002"], risk="medium",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["-cmd", "-quickurl", "{{url}}", "-quickout", "/tmp/zap-report.html"],
      scope_arg="url",
      output_artifacts=["/tmp/zap-report.html"]))

add(t("sslscan_run", "sslscan", "web",
      "SSL/TLS configuration scanner.",
      timeout=300, mitre=["T1592.002"], risk="low",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["{{target}}"], scope_arg="target"))

add(t("testssl", "testssl", "web",
      "Comprehensive TLS/SSL test (ciphers, protocols, vulns).",
      timeout=900, mitre=["T1592.002"], risk="low",
      args_schema=S({
          "target": P_str(),
          "fast":   P_bool(default=True),
      }, ["target"]),
      argv=["{{?fast}}--fast{{/fast}}", "{{target}}"], scope_arg="target"))

add(t("sslyze_run", "sslyze", "web",
      "Fast TLS server analyzer (Python).",
      timeout=600, mitre=["T1592.002"], risk="low",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["{{target}}"], scope_arg="target"))

add(t("hakrawler_run", "hakrawler", "web",
      "Fast web crawler that surfaces URLs and JS endpoints.",
      timeout=300, mitre=["T1595.002"], risk="low",
      args_schema=S({"url": P_str()}, ["url"]),
      argv=["-url", "{{url}}", "-plain"], scope_arg="url"))

add(t("paramspider_run", "paramspider", "web",
      "Mine URL parameters from web archives.",
      timeout=300, mitre=["T1595.003"], risk="low",
      args_schema=S({"domain": P_str()}, ["domain"]),
      argv=["-d", "{{domain}}"], scope_arg="domain"))


# ─── AD / DOMAIN ──────────────────────────────────────────────────────────
add(t("netexec_smb", "netexec", "ad",
      "SMB enumeration & exploitation (formerly CrackMapExec).",
      timeout=900, mitre=["T1021.002", "T1110.003"], risk="high",
      when="Map SMB hosts in a network, validate credentials, dump SAM/LSA when authorized.",
      how="`--shares`, `--users`, `--sam`, `-x` for command exec. ALWAYS confirm scope before -x.",
      refs=["https://github.com/Pennyw0rth/NetExec"],
      args_schema=S({
          "target": P_str(),
          "user":   P_str(default=""),
          "passwd": P_str(default=""),
          "hash":   P_str(default=""),
          "domain": P_str(default=""),
          "module": P_enum(["", "shares", "users", "sam", "lsa", "ntds"], default=""),
      }, ["target"]),
      argv=["smb", "{{target}}",
            "{{?user}}-u{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?passwd}}-p{{/passwd}}", "{{?passwd}}{{passwd}}{{/passwd}}",
            "{{?hash}}-H{{/hash}}", "{{?hash}}{{hash}}{{/hash}}",
            "{{?domain}}-d{{/domain}}", "{{?domain}}{{domain}}{{/domain}}",
            "{{?module}}--{{/module}}{{?module}}{{module}}{{/module}}"],
      scope_arg="target"))

add(t("netexec_winrm", "netexec", "ad",
      "WinRM enumeration & command execution.",
      timeout=900, mitre=["T1021.006"], risk="high",
      args_schema=S({
          "target": P_str(),
          "user":   P_str(default=""),
          "passwd": P_str(default=""),
          "hash":   P_str(default=""),
          "command": P_str(default=""),
      }, ["target"]),
      argv=["winrm", "{{target}}",
            "{{?user}}-u{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?passwd}}-p{{/passwd}}", "{{?passwd}}{{passwd}}{{/passwd}}",
            "{{?hash}}-H{{/hash}}", "{{?hash}}{{hash}}{{/hash}}",
            "{{?command}}-x{{/command}}", "{{?command}}{{command}}{{/command}}"],
      scope_arg="target"))

add(t("netexec_ldap", "netexec", "ad",
      "LDAP enumeration via netexec (users/groups/ASREP/Kerberoast).",
      timeout=900, mitre=["T1087.002"], risk="medium",
      args_schema=S({
          "target": P_str(),
          "user":   P_str(default=""),
          "passwd": P_str(default=""),
          "module": P_enum(["", "asreproast", "kerberoasting", "users", "groups"], default=""),
      }, ["target"]),
      argv=["ldap", "{{target}}",
            "{{?user}}-u{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?passwd}}-p{{/passwd}}", "{{?passwd}}{{passwd}}{{/passwd}}",
            "{{?module}}-M{{/module}}", "{{?module}}{{module}}{{/module}}"],
      scope_arg="target"))

add(t("impacket_secretsdump", "impacket-secretsdump", "ad",
      "Dump SAM/LSA/NTDS via remote registry / DRSUAPI.",
      timeout=1200, mitre=["T1003.001", "T1003.005"], risk="high",
      when="You have valid creds (or hash) for a Domain Admin and need to extract NTDS.dit.",
      how="`drsuapi` (default) needs DA. `vss` requires admin on DC. NEVER run on prod without IR coordination.",
      refs=["https://github.com/fortra/impacket"],
      args_schema=S({
          "domain":   P_str(),
          "username": P_str(),
          "password": P_str(default=""),
          "hashes":   P_str(default="", description="LM:NT"),
          "dc_ip":    P_str(),
      }, ["domain", "username", "dc_ip"]),
      argv=["{{domain}}/{{username}}{{?password}}:{{password}}{{/password}}@{{dc_ip}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}",
            "-just-dc"], scope_arg="dc_ip"))

add(t("impacket_getuserspns", "impacket-GetUserSPNs", "ad",
      "Kerberoasting — request TGS for service accounts.",
      timeout=600, mitre=["T1558.003"], risk="medium",
      when="You have any valid AD user credential and want to harvest service-account TGS for offline cracking.",
      args_schema=S({
          "domain":   P_str(),
          "username": P_str(),
          "password": P_str(default=""),
          "hashes":   P_str(default=""),
          "dc_ip":    P_str(),
      }, ["domain", "username", "dc_ip"]),
      argv=["{{domain}}/{{username}}{{?password}}:{{password}}{{/password}}",
            "-dc-ip", "{{dc_ip}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}",
            "-request"], scope_arg="dc_ip"))

add(t("impacket_getnpusers", "impacket-GetNPUsers", "ad",
      "ASREP roasting — find users without Kerberos pre-auth.",
      timeout=600, mitre=["T1558.004"], risk="medium",
      when="Unauthenticated bootstrap when you have a list of usernames and a reachable DC.",
      args_schema=S({
          "domain":    P_str(),
          "userfile":  P_str(),
          "dc_ip":     P_str(),
      }, ["domain", "userfile", "dc_ip"]),
      argv=["{{domain}}/", "-usersfile", "{{userfile}}",
            "-dc-ip", "{{dc_ip}}", "-no-pass", "-request"],
      scope_arg="dc_ip"))

add(t("impacket_psexec", "impacket-psexec", "ad",
      "Remote code execution via SMB (psexec-style).",
      timeout=600, mitre=["T1021.002"], risk="high",
      interactive=True, interaction=PTY_GENERIC,
      args_schema=S({
          "domain":   P_str(default=""),
          "username": P_str(),
          "password": P_str(default=""),
          "hashes":   P_str(default=""),
          "target":   P_str(),
      }, ["username", "target"]),
      argv=["{{?domain}}{{domain}}/{{/domain}}{{username}}{{?password}}:{{password}}{{/password}}@{{target}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}"],
      scope_arg="target"))

add(t("impacket_smbexec", "impacket-smbexec", "ad",
      "Semi-interactive shell over SMB (no service install).",
      timeout=600, mitre=["T1021.002"], risk="high",
      interactive=True, interaction=PTY_GENERIC,
      args_schema=S({
          "username": P_str(), "password": P_str(default=""),
          "hashes": P_str(default=""), "target": P_str(),
          "domain": P_str(default=""),
      }, ["username", "target"]),
      argv=["{{?domain}}{{domain}}/{{/domain}}{{username}}{{?password}}:{{password}}{{/password}}@{{target}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}"],
      scope_arg="target"))

add(t("impacket_wmiexec", "impacket-wmiexec", "ad",
      "Semi-interactive shell via WMI.",
      timeout=600, mitre=["T1047"], risk="high",
      interactive=True, interaction=PTY_GENERIC,
      args_schema=S({
          "username": P_str(), "password": P_str(default=""),
          "hashes": P_str(default=""), "target": P_str(),
          "domain": P_str(default=""),
      }, ["username", "target"]),
      argv=["{{?domain}}{{domain}}/{{/domain}}{{username}}{{?password}}:{{password}}{{/password}}@{{target}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}"],
      scope_arg="target"))

add(t("evil_winrm", "evil-winrm", "ad",
      "Interactive WinRM shell with offensive helpers.",
      timeout=3600, mitre=["T1021.006"], risk="high",
      interactive=True, interaction=PTY_EVILWINRM,
      when="You have valid creds/hash for a Windows host with WinRM open (5985/5986).",
      why="Built-in helpers: file upload/download, AMSI bypass, in-memory script load.",
      refs=["https://github.com/Hackplayers/evil-winrm"],
      args_schema=S({
          "target":   P_str(),
          "user":     P_str(),
          "password": P_str(default=""),
          "hash":     P_str(default=""),
      }, ["target", "user"]),
      argv=["-i", "{{target}}", "-u", "{{user}}",
            "{{?password}}-p{{/password}}", "{{?password}}{{password}}{{/password}}",
            "{{?hash}}-H{{/hash}}", "{{?hash}}{{hash}}{{/hash}}"],
      scope_arg="target"))

add(t("kerbrute_userenum", "kerbrute", "ad",
      "Enumerate valid AD usernames via Kerberos pre-auth (silent).",
      timeout=600, mitre=["T1087.002"], risk="medium",
      args_schema=S({
          "domain":   P_str(),
          "userfile": P_str(),
          "dc":       P_str(),
      }, ["domain", "userfile", "dc"]),
      argv=["userenum", "-d", "{{domain}}", "--dc", "{{dc}}", "{{userfile}}"],
      scope_arg="dc"))

add(t("kerbrute_passwordspray", "kerbrute", "ad",
      "Password spray AD via Kerberos.",
      timeout=900, mitre=["T1110.003"], risk="high",
      args_schema=S({
          "domain":   P_str(),
          "userfile": P_str(),
          "password": P_str(),
          "dc":       P_str(),
      }, ["domain", "userfile", "password", "dc"]),
      argv=["passwordspray", "-d", "{{domain}}", "--dc", "{{dc}}",
            "{{userfile}}", "{{password}}"], scope_arg="dc"))

add(t("rpcclient_query", "rpcclient", "ad",
      "MS-RPC queries (enumdomusers, lookupnames, etc.).",
      timeout=300, mitre=["T1087.002"], risk="medium",
      args_schema=S({
          "target": P_str(),
          "user":   P_str(default=""),
          "passwd": P_str(default=""),
          "command": P_str(default="enumdomusers"),
      }, ["target"]),
      argv=["-U", "{{user}}%{{passwd}}", "{{target}}",
            "-c", "{{command}}"], scope_arg="target"))

add(t("smbclient_run", "smbclient", "ad",
      "Interactive/CLI SMB share access.",
      timeout=600, mitre=["T1021.002"], risk="medium",
      args_schema=S({
          "share":  P_str(description="//host/share"),
          "user":   P_str(default=""),
          "passwd": P_str(default=""),
          "command": P_str(default="ls"),
      }, ["share"]),
      argv=["{{share}}", "-U", "{{user}}%{{passwd}}",
            "-c", "{{command}}"], scope_arg=None))

add(t("smbmap_enum", "smbmap", "ad",
      "Enumerate SMB shares & permissions.",
      timeout=600, mitre=["T1135"], risk="medium",
      args_schema=S({
          "host": P_str(),
          "user": P_str(default=""),
          "passwd": P_str(default=""),
          "domain": P_str(default=""),
      }, ["host"]),
      argv=["-H", "{{host}}",
            "{{?user}}-u{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?passwd}}-p{{/passwd}}", "{{?passwd}}{{passwd}}{{/passwd}}",
            "{{?domain}}-d{{/domain}}", "{{?domain}}{{domain}}{{/domain}}"],
      scope_arg="host"))

add(t("enum4linux_run", "enum4linux", "ad",
      "Enumerate Windows/Samba systems.",
      timeout=600, mitre=["T1087.002"], risk="medium",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["-a", "{{target}}"], scope_arg="target"))

add(t("enum4linux_ng", "enum4linux-ng", "ad",
      "Modern rewrite of enum4linux (JSON output).",
      timeout=600, mitre=["T1087.002"], risk="medium",
      args_schema=S({"target": P_str()}, ["target"]),
      argv=["-A", "{{target}}", "-oJ", "/tmp/enum4linux-ng.json"],
      scope_arg="target", parser="jsonl",
      output_artifacts=["/tmp/enum4linux-ng.json"]))

add(t("ldapsearch_query", "ldapsearch", "ad",
      "LDAP query tool (OpenLDAP).",
      timeout=300, mitre=["T1087.002"], risk="medium",
      args_schema=S({
          "uri":      P_str(description="ldap://host or ldaps://host"),
          "base_dn":  P_str(),
          "bind_dn":  P_str(default=""),
          "password": P_str(default=""),
          "filter":   P_str(default="(objectClass=*)"),
      }, ["uri", "base_dn"]),
      argv=["-x", "-H", "{{uri}}", "-b", "{{base_dn}}",
            "{{?bind_dn}}-D{{/bind_dn}}", "{{?bind_dn}}{{bind_dn}}{{/bind_dn}}",
            "{{?password}}-w{{/password}}", "{{?password}}{{password}}{{/password}}",
            "{{filter}}"]))

add(t("certipy_find", "certipy", "ad",
      "AD-CS enumeration for ESC1-ESC11 templates.",
      timeout=600, mitre=["T1649"], risk="medium",
      args_schema=S({
          "domain":   P_str(),
          "username": P_str(),
          "password": P_str(default=""),
          "hashes":   P_str(default=""),
          "dc_ip":    P_str(),
      }, ["domain", "username", "dc_ip"]),
      argv=["find", "-u", "{{username}}@{{domain}}",
            "{{?password}}-p{{/password}}", "{{?password}}{{password}}{{/password}}",
            "{{?hashes}}-hashes{{/hashes}}", "{{?hashes}}{{hashes}}{{/hashes}}",
            "-dc-ip", "{{dc_ip}}", "-vulnerable", "-stdout"],
      scope_arg="dc_ip"))

add(t("bloodhound_python", "bloodhound-python", "ad",
      "Python ingestor for BloodHound (LDAP+SMB).",
      timeout=1800, mitre=["T1482"], risk="medium",
      args_schema=S({
          "domain": P_str(),
          "username": P_str(),
          "password": P_str(default=""),
          "dc": P_str(),
          "collection": P_str(default="Default"),
      }, ["domain", "username", "dc"]),
      argv=["-d", "{{domain}}", "-u", "{{username}}",
            "{{?password}}-p{{/password}}", "{{?password}}{{password}}{{/password}}",
            "-dc", "{{dc}}", "-c", "{{collection}}"],
      scope_arg="dc",
      output_artifacts=["./*.json"]))

add(t("responder_run", "responder", "ad",
      "LLMNR/NBT-NS/MDNS poisoner & SMB credential capture.",
      timeout=3600, mitre=["T1557.001"], risk="high",
      sudo=True, sudo_reason="Binds privileged ports (53, 88, 135, 137, 139, 445, 1433, 5353)",
      when="On-network credential harvesting on a Windows segment.",
      how="ALWAYS coordinate with engagement scope; can disrupt name resolution. Use `-A` for analyze-only first.",
      refs=["https://github.com/lgandx/Responder"],
      args_schema=S({
          "interface": P_str(),
          "analyze_only": P_bool(default=False),
      }, ["interface"]),
      argv=["-I", "{{interface}}", "{{?analyze_only}}-A{{/analyze_only}}"],
      output_artifacts=["/usr/share/responder/logs/Responder-Session.log"]))

add(t("mitm6_run", "mitm6", "ad",
      "IPv6 MITM via DHCPv6 + DNS takeover.",
      timeout=3600, mitre=["T1557.002"], risk="high",
      sudo=True, sudo_reason="Raw socket + DHCP server",
      args_schema=S({
          "interface": P_str(),
          "domain": P_str(),
      }, ["interface", "domain"]),
      argv=["-i", "{{interface}}", "-d", "{{domain}}", "--no-ra"]))


# ─── CREDENTIALS ──────────────────────────────────────────────────────────
add(t("hashcat_attack", "hashcat", "creds",
      "GPU-accelerated password recovery.",
      timeout=86400, mitre=["T1110.002"], risk="medium",
      when="Crack a captured hash file with a wordlist or rules.",
      how="`-m` selects hash mode (1000=NTLM, 22000=WPA, 13100=Kerberoast); see `hashcat -h`.",
      refs=["https://hashcat.net/wiki/"],
      args_schema=S({
          "hash_mode": P_int(description="see hashcat --help"),
          "hash_file": P_str(),
          "wordlist":  P_str(default="/usr/share/wordlists/rockyou.txt"),
          "rules":     P_str(default=""),
          "attack_mode": P_enum(["0", "1", "3", "6", "7"], default="0"),
      }, ["hash_mode", "hash_file"]),
      argv=["-m", "{{hash_mode}}", "-a", "{{attack_mode}}",
            "{{hash_file}}", "{{wordlist}}",
            "{{?rules}}-r{{/rules}}", "{{?rules}}{{rules}}{{/rules}}",
            "--quiet"]))

add(t("john_attack", "john", "creds",
      "John the Ripper — CPU password cracker.",
      timeout=86400, mitre=["T1110.002"], risk="medium",
      args_schema=S({
          "hash_file": P_str(),
          "format":    P_str(default=""),
          "wordlist":  P_str(default="/usr/share/wordlists/rockyou.txt"),
      }, ["hash_file"]),
      argv=["{{?format}}--format={{format}}{{/format}}",
            "--wordlist={{wordlist}}", "{{hash_file}}"]))

add(t("hydra_brute", "hydra", "creds",
      "Network login brute-forcer (SSH/FTP/HTTP/etc.).",
      timeout=3600, mitre=["T1110.001"], risk="high",
      args_schema=S({
          "service": P_str(description="ssh, ftp, http-post-form, ..."),
          "target":  P_str(),
          "user":    P_str(default=""),
          "userlist": P_str(default=""),
          "passlist": P_str(),
          "threads": P_int(default=4),
      }, ["service", "target", "passlist"]),
      argv=["{{?user}}-l{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?userlist}}-L{{/userlist}}", "{{?userlist}}{{userlist}}{{/userlist}}",
            "-P", "{{passlist}}", "-t", "{{threads}}",
            "{{target}}", "{{service}}"], scope_arg="target"))

add(t("medusa_brute", "medusa", "creds",
      "Parallel brute-force login auditor.",
      timeout=3600, mitre=["T1110.001"], risk="high",
      args_schema=S({
          "module": P_str(description="ssh, smbnt, mssql, ..."),
          "target": P_str(),
          "user":   P_str(default=""),
          "userlist": P_str(default=""),
          "passlist": P_str(),
      }, ["module", "target", "passlist"]),
      argv=["-h", "{{target}}",
            "{{?user}}-u{{/user}}", "{{?user}}{{user}}{{/user}}",
            "{{?userlist}}-U{{/userlist}}", "{{?userlist}}{{userlist}}{{/userlist}}",
            "-P", "{{passlist}}", "-M", "{{module}}"], scope_arg="target"))

add(t("ncrack_brute", "ncrack", "creds",
      "High-speed network auth cracker (RDP/SSH/SMB/HTTP).",
      timeout=3600, mitre=["T1110.001"], risk="high",
      args_schema=S({
          "target":   P_str(description="proto://host:port"),
          "userlist": P_str(),
          "passlist": P_str(),
      }, ["target", "userlist", "passlist"]),
      argv=["-U", "{{userlist}}", "-P", "{{passlist}}", "{{target}}"]))

add(t("name_that_hash", "name-that-hash", "creds",
      "Identify hash type quickly.",
      timeout=60, risk="low",
      args_schema=S({"hash": P_str()}, ["hash"]),
      argv=["-t", "{{hash}}"]))

add(t("hashid_run", "hashid", "creds",
      "Identify possible hash types.",
      timeout=30, risk="low",
      args_schema=S({"hash": P_str()}, ["hash"]),
      argv=["{{hash}}"]))

add(t("hash_identifier", "hash-identifier", "creds",
      "Interactive hash identifier (legacy).",
      timeout=60, risk="low", interactive=True, interaction=PTY_GENERIC,
      args_schema=S({}, []), argv=[]))

add(t("crackmapexec_alias", "netexec", "creds",
      "Alias kept for compatibility — see netexec_smb/netexec_winrm.",
      timeout=600, risk="medium",
      args_schema=S({"args": P_str(default="--help")}, []),
      argv=["{{args}}"]))

add(t("cewl_wordlist", "cewl", "creds",
      "Generate wordlists from a website's text.",
      timeout=600, mitre=["T1589.001"], risk="low",
      args_schema=S({
          "url":   P_str(),
          "depth": P_int(default=2),
          "min_len": P_int(default=5),
      }, ["url"]),
      argv=["-d", "{{depth}}", "-m", "{{min_len}}", "{{url}}"], scope_arg="url"))

add(t("crunch_wordlist", "crunch", "creds",
      "Generate wordlists with character sets and patterns.",
      timeout=300, risk="low",
      args_schema=S({
          "min_len": P_int(),
          "max_len": P_int(),
          "charset": P_str(default="abcdefghijklmnopqrstuvwxyz"),
          "output":  P_str(default="/tmp/wordlist.txt"),
      }, ["min_len", "max_len"]),
      argv=["{{min_len}}", "{{max_len}}", "{{charset}}", "-o", "{{output}}"],
      output_artifacts=["{{output}}"]))


# ─── NETWORK / MITM / TRAFFIC ─────────────────────────────────────────────
add(t("tcpdump_capture", "tcpdump", "network",
      "Packet capture (libpcap).",
      timeout=600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="CAP_NET_RAW for raw packet capture",
      args_schema=S({
          "interface": P_str(),
          "filter":    P_str(default=""),
          "count":     P_int(default=1000),
          "output":    P_str(default="/tmp/capture.pcap"),
      }, ["interface"]),
      argv=["-i", "{{interface}}", "-c", "{{count}}",
            "-w", "{{output}}", "{{?filter}}{{filter}}{{/filter}}"],
      output_artifacts=["{{output}}"]))

add(t("tshark_capture", "tshark", "network",
      "CLI Wireshark — capture or read pcap with display filters.",
      timeout=600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="CAP_NET_RAW",
      args_schema=S({
          "interface": P_str(default=""),
          "read_file": P_str(default=""),
          "filter":    P_str(default=""),
          "fields":    P_str(default=""),
      }),
      argv=["{{?interface}}-i{{/interface}}", "{{?interface}}{{interface}}{{/interface}}",
            "{{?read_file}}-r{{/read_file}}", "{{?read_file}}{{read_file}}{{/read_file}}",
            "{{?filter}}-Y{{/filter}}", "{{?filter}}{{filter}}{{/filter}}",
            "{{?fields}}-T{{/fields}}", "{{?fields}}fields{{/fields}}"]))

add(t("tcpflow_reassemble", "tcpflow", "network",
      "Reassemble TCP streams from pcap/live capture.",
      timeout=600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Raw socket",
      args_schema=S({
          "interface": P_str(default=""),
          "pcap":      P_str(default=""),
          "outdir":    P_str(default="/tmp/tcpflow"),
      }),
      argv=["{{?interface}}-i{{/interface}}", "{{?interface}}{{interface}}{{/interface}}",
            "{{?pcap}}-r{{/pcap}}", "{{?pcap}}{{pcap}}{{/pcap}}",
            "-o", "{{outdir}}"], output_artifacts=["{{outdir}}/"]))

add(t("ngrep_run", "ngrep", "network",
      "grep for network packets (libpcap).",
      timeout=600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Raw socket",
      args_schema=S({
          "pattern": P_str(),
          "interface": P_str(),
          "filter": P_str(default=""),
      }, ["pattern", "interface"]),
      argv=["-d", "{{interface}}", "-q", "{{pattern}}", "{{?filter}}{{filter}}{{/filter}}"]))

add(t("netcat_connect", "nc", "network",
      "TCP/UDP swiss-army knife (connect/listen).",
      timeout=120, risk="medium",
      args_schema=S({
          "host": P_str(default=""),
          "port": P_int(),
          "listen": P_bool(default=False),
          "udp":   P_bool(default=False),
      }, ["port"]),
      argv=["{{?listen}}-l{{/listen}}", "{{?udp}}-u{{/udp}}",
            "{{?host}}{{host}}{{/host}}", "{{port}}"]))

add(t("ncat_connect", "ncat", "network",
      "Modern netcat (nmap project) with TLS support.",
      timeout=120, risk="medium",
      args_schema=S({
          "host": P_str(default=""), "port": P_int(),
          "listen": P_bool(default=False), "ssl": P_bool(default=False),
      }, ["port"]),
      argv=["{{?listen}}-l{{/listen}}", "{{?ssl}}--ssl{{/ssl}}",
            "{{?host}}{{host}}{{/host}}", "{{port}}"]))

add(t("socat_relay", "socat", "network",
      "Relay/forward connections between endpoints.",
      timeout=3600, risk="medium",
      args_schema=S({
          "from": P_str(description="e.g. TCP-LISTEN:8080,fork"),
          "to":   P_str(description="e.g. TCP:internal:80"),
      }, ["from", "to"]),
      argv=["{{from}}", "{{to}}"]))

add(t("bettercap_run", "bettercap", "network",
      "Network attack/MITM framework.",
      timeout=3600, mitre=["T1557.002", "T1040"], risk="high",
      sudo=True, sudo_reason="Raw socket, ARP spoofing",
      interactive=True, interaction={
          "type": "pty",
          "prompts": [r"\d+\.\d+\.\d+\.\d+/\d+ > "],
          "commands_help": "Type `help` inside bettercap; `arp.spoof on`, `net.probe on`, etc.",
      },
      when="Active MITM operations on an authorized internal segment.",
      args_schema=S({"interface": P_str()}, ["interface"]),
      argv=["-iface", "{{interface}}"]))

add(t("ettercap_text", "ettercap", "network",
      "ARP/MITM tool (text mode).",
      timeout=3600, mitre=["T1557.002"], risk="high",
      sudo=True, sudo_reason="Raw socket",
      args_schema=S({
          "interface": P_str(),
          "targets": P_str(default="/ /"),
      }, ["interface"]),
      argv=["-T", "-q", "-i", "{{interface}}", "-M", "arp", "{{targets}}"]))

add(t("arpspoof_run", "arpspoof", "network",
      "ARP cache poisoning.",
      timeout=3600, mitre=["T1557.002"], risk="high",
      sudo=True, sudo_reason="Raw socket",
      args_schema=S({
          "interface": P_str(),
          "target":    P_str(),
          "gateway":   P_str(),
      }, ["interface", "target", "gateway"]),
      argv=["-i", "{{interface}}", "-t", "{{target}}", "{{gateway}}"], scope_arg="target"))

add(t("yersinia_attack", "yersinia", "network",
      "L2 attacks (STP, CDP, DHCP, HSRP, ...).",
      timeout=600, mitre=["T1499"], risk="high",
      sudo=True, sudo_reason="Raw socket",
      interactive=True, interaction=PTY_GENERIC,
      args_schema=S({}, []), argv=["-I"]))

add(t("mitmproxy_run", "mitmproxy", "network",
      "Interactive HTTPS proxy (mitmproxy TUI).",
      timeout=3600, mitre=["T1557.001"], risk="high",
      interactive=True, interaction=PTY_MITMPROXY,
      args_schema=S({
          "port": P_int(default=8080),
          "mode": P_enum(["regular", "transparent", "reverse"], default="regular"),
      }),
      argv=["-p", "{{port}}", "--mode", "{{mode}}"]))

add(t("mitmdump_run", "mitmdump", "network",
      "Headless mitmproxy variant for scripting.",
      timeout=3600, risk="high",
      args_schema=S({
          "port": P_int(default=8080),
          "script": P_str(default=""),
      }),
      argv=["-p", "{{port}}", "{{?script}}-s{{/script}}", "{{?script}}{{script}}{{/script}}"]))


# ─── WIRELESS ─────────────────────────────────────────────────────────────
add(t("airmon_ng", "airmon-ng", "wireless",
      "Enable/disable monitor mode on wireless interface.",
      timeout=60, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Configures network interface",
      args_schema=S({
          "action":    P_enum(["start", "stop", "check"], default="start"),
          "interface": P_str(),
      }, ["interface"]),
      argv=["{{action}}", "{{interface}}"]))

add(t("airodump_ng", "airodump-ng", "wireless",
      "802.11 packet capture / AP discovery.",
      timeout=600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(description="must be in monitor mode (e.g. wlan0mon)"),
          "channel":   P_int(default=0),
          "bssid":     P_str(default=""),
          "output":    P_str(default="/tmp/airodump"),
      }, ["interface"]),
      argv=["{{?bssid}}--bssid{{/bssid}}", "{{?bssid}}{{bssid}}{{/bssid}}",
            "{{?channel}}-c{{/channel}}", "{{?channel}}{{channel}}{{/channel}}",
            "-w", "{{output}}", "{{interface}}"],
      output_artifacts=["{{output}}-01.cap"]))

add(t("aireplay_ng", "aireplay-ng", "wireless",
      "Inject 802.11 frames (deauth, fakeauth, ARP replay).",
      timeout=600, mitre=["T1499"], risk="high",
      sudo=True, sudo_reason="Monitor mode + injection",
      args_schema=S({
          "interface": P_str(),
          "attack":    P_enum(["deauth", "fakeauth", "arpreplay"], default="deauth"),
          "bssid":     P_str(),
          "client":    P_str(default=""),
          "count":     P_int(default=10),
      }, ["interface", "bssid"]),
      argv=["--{{attack}}", "{{count}}", "-a", "{{bssid}}",
            "{{?client}}-c{{/client}}", "{{?client}}{{client}}{{/client}}",
            "{{interface}}"]))

add(t("aircrack_ng", "aircrack-ng", "wireless",
      "WEP/WPA/WPA2 dictionary cracker (CPU).",
      timeout=86400, mitre=["T1110.002"], risk="medium",
      args_schema=S({
          "pcap":     P_str(),
          "wordlist": P_str(default="/usr/share/wordlists/rockyou.txt"),
          "bssid":    P_str(default=""),
      }, ["pcap"]),
      argv=["{{?bssid}}-b{{/bssid}}", "{{?bssid}}{{bssid}}{{/bssid}}",
            "-w", "{{wordlist}}", "{{pcap}}"]))

add(t("wifite_run", "wifite", "wireless",
      "Automated WPA/WEP/WPS auditor.",
      timeout=3600, mitre=["T1110.002"], risk="high",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(default=""),
          "wpa_only":  P_bool(default=True),
      }),
      argv=["{{?interface}}-i{{/interface}}", "{{?interface}}{{interface}}{{/interface}}",
            "{{?wpa_only}}--wpa{{/wpa_only}}"]))

add(t("reaver_wps", "reaver", "wireless",
      "WPS PIN brute-force attack.",
      timeout=86400, mitre=["T1110.001"], risk="high",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(),
          "bssid":     P_str(),
      }, ["interface", "bssid"]),
      argv=["-i", "{{interface}}", "-b", "{{bssid}}", "-vv"]))

add(t("hcxdumptool_run", "hcxdumptool", "wireless",
      "Capture WiFi handshakes / PMKID for hashcat.",
      timeout=1800, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(),
          "output":    P_str(default="/tmp/wifi-dump.pcapng"),
      }, ["interface"]),
      argv=["-i", "{{interface}}", "-o", "{{output}}", "--enable_status=1"],
      output_artifacts=["{{output}}"]))

add(t("hcxpcapngtool", "hcxpcapngtool", "wireless",
      "Convert .pcapng captures to hashcat 22000 format.",
      timeout=120, risk="low",
      args_schema=S({
          "input":  P_str(),
          "output": P_str(default="/tmp/wifi.22000"),
      }, ["input"]),
      argv=["-o", "{{output}}", "{{input}}"],
      output_artifacts=["{{output}}"]))

add(t("kismet_run", "kismet", "wireless",
      "Wireless network detector / sniffer.",
      timeout=3600, mitre=["T1040"], risk="medium",
      sudo=True, sudo_reason="Raw socket / monitor mode",
      args_schema=S({"interface": P_str()}, ["interface"]),
      argv=["-c", "{{interface}}", "--no-ncurses"]))

add(t("bully_wps", "bully", "wireless",
      "Alternative WPS brute-forcer.",
      timeout=86400, mitre=["T1110.001"], risk="high",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(), "bssid": P_str(),
      }, ["interface", "bssid"]),
      argv=["{{interface}}", "-b", "{{bssid}}"]))

add(t("mdk4_attack", "mdk4", "wireless",
      "WiFi DoS/test toolkit.",
      timeout=600, mitre=["T1499"], risk="high",
      sudo=True, sudo_reason="Monitor mode",
      args_schema=S({
          "interface": P_str(),
          "test":      P_enum(["d", "b", "a", "p"], default="d"),
      }, ["interface"]),
      argv=["{{interface}}", "{{test}}"]))


# ─── REVERSE ENGINEERING / FORENSICS ──────────────────────────────────────
add(t("strings_dump", "strings", "re",
      "Print printable strings in a binary.",
      timeout=120, risk="low",
      args_schema=S({
          "file": P_str(),
          "min_len": P_int(default=4),
      }, ["file"]),
      argv=["-n", "{{min_len}}", "{{file}}"]))

add(t("file_id", "file", "re",
      "Identify file type via magic bytes.",
      timeout=30, risk="low",
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["{{file}}"]))

add(t("checksec_check", "checksec", "re",
      "Check binary security mitigations (NX/PIE/RELRO/Canary).",
      timeout=60, risk="low",
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["--file={{file}}"]))

add(t("readelf_dump", "readelf", "re",
      "Display ELF file information.",
      timeout=60, risk="low",
      args_schema=S({"file": P_str(), "all": P_bool(default=True)}, ["file"]),
      argv=["{{?all}}-a{{/all}}", "{{file}}"]))

add(t("objdump_disasm", "objdump", "re",
      "Disassemble binaries / inspect sections.",
      timeout=120, risk="low",
      args_schema=S({"file": P_str(), "disasm": P_bool(default=True)}, ["file"]),
      argv=["{{?disasm}}-d{{/disasm}}", "{{file}}"]))

add(t("nm_symbols", "nm", "re",
      "List symbols from object files.",
      timeout=60, risk="low",
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["{{file}}"]))

add(t("ltrace_run", "ltrace", "re",
      "Trace library calls of a process.",
      timeout=300, mitre=["T1055"], risk="medium",
      args_schema=S({"command": P_str()}, ["command"]),
      argv=["{{command}}"]))

add(t("strace_run", "strace", "re",
      "Trace system calls.",
      timeout=300, mitre=["T1057"], risk="medium",
      args_schema=S({"command": P_str()}, ["command"]),
      argv=["-f", "{{command}}"]))

add(t("radare2_session", "r2", "re",
      "Interactive radare2 disassembler/debugger.",
      timeout=3600, risk="medium",
      interactive=True, interaction={
          "type": "pty",
          "prompts": [r"\[0x[0-9a-f]+\]> "],
          "commands_help": "aaa = analyze all; pdf = print disasm function; afl = list functions; q = quit.",
      },
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["-A", "{{file}}"]))

add(t("rabin2_info", "rabin2", "re",
      "Static binary information (radare2).",
      timeout=120, risk="low",
      args_schema=S({"file": P_str(), "info": P_str(default="-I")}, ["file"]),
      argv=["{{info}}", "{{file}}"]))

add(t("ghidra_headless", "analyzeHeadless", "re",
      "Run Ghidra in headless analysis mode.",
      timeout=3600, risk="medium",
      args_schema=S({
          "project_dir": P_str(default="/tmp/ghidra-projects"),
          "project_name": P_str(default="auto"),
          "import":      P_str(),
          "post_script": P_str(default=""),
      }, ["import"]),
      argv=["{{project_dir}}", "{{project_name}}", "-import", "{{import}}",
            "{{?post_script}}-postScript{{/post_script}}", "{{?post_script}}{{post_script}}{{/post_script}}"]))

add(t("gdb_session", "gdb", "re",
      "GNU debugger (interactive).",
      timeout=3600, risk="medium",
      interactive=True, interaction={
          "type": "pty",
          "prompts": [r"\(gdb\) "],
          "commands_help": "run, break, info reg, x/i, c, q.",
      },
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["{{file}}"]))

add(t("volatility3_run", "vol", "re",
      "Memory forensics framework (Volatility 3).",
      timeout=1800, mitre=["T1057"], risk="medium",
      args_schema=S({
          "memory_image": P_str(),
          "plugin":       P_str(default="windows.pslist"),
      }, ["memory_image"]),
      argv=["-f", "{{memory_image}}", "{{plugin}}"]))

add(t("foremost_carve", "foremost", "re",
      "Carve files from disk images.",
      timeout=1800, risk="low",
      args_schema=S({
          "input": P_str(),
          "output": P_str(default="/tmp/foremost-out"),
      }, ["input"]),
      argv=["-i", "{{input}}", "-o", "{{output}}"],
      output_artifacts=["{{output}}/"]))

add(t("binwalk_scan", "binwalk", "re",
      "Firmware analysis: identify embedded files / extract.",
      timeout=600, risk="low",
      args_schema=S({
          "file": P_str(),
          "extract": P_bool(default=False),
      }, ["file"]),
      argv=["{{?extract}}-e{{/extract}}", "{{file}}"]))

add(t("steghide_extract", "steghide", "re",
      "Hide/extract data from images & audio.",
      timeout=300, risk="low",
      args_schema=S({
          "action": P_enum(["embed", "extract", "info"], default="extract"),
          "file":   P_str(),
          "passphrase": P_str(default=""),
      }, ["file"]),
      argv=["{{action}}", "-sf", "{{file}}",
            "{{?passphrase}}-p{{/passphrase}}", "{{?passphrase}}{{passphrase}}{{/passphrase}}"]))

add(t("exiftool_meta", "exiftool", "re",
      "Read/write image & document metadata.",
      timeout=60, risk="low",
      args_schema=S({"file": P_str()}, ["file"]),
      argv=["{{file}}"]))

add(t("xxd_hex", "xxd", "re",
      "Hexdump utility.",
      timeout=60, risk="low",
      args_schema=S({"file": P_str(), "len": P_int(default=256)}, ["file"]),
      argv=["-l", "{{len}}", "{{file}}"]))


# ─── EXPLOITATION / POST-EXPLOIT / C2 ─────────────────────────────────────
add(t("msfconsole_session", "msfconsole", "post-exploit",
      "Metasploit console (interactive).",
      timeout=14400, mitre=["T1059"], risk="high",
      interactive=True, interaction=PTY_MSF,
      when="Multi-step exploitation requiring stateful module configuration.",
      how="ALWAYS use `setg LHOST` etc. carefully; avoid dangerous payloads on production. `exit -y` to quit.",
      args_schema=S({
          "quiet": P_bool(default=True),
          "resource_script": P_str(default=""),
      }),
      argv=["{{?quiet}}-q{{/quiet}}",
            "{{?resource_script}}-r{{/resource_script}}", "{{?resource_script}}{{resource_script}}{{/resource_script}}"]))

add(t("msfvenom_payload", "msfvenom", "post-exploit",
      "Generate Metasploit payloads.",
      timeout=300, mitre=["T1027"], risk="high",
      args_schema=S({
          "payload": P_str(description="e.g. windows/x64/meterpreter/reverse_tcp"),
          "lhost":   P_str(),
          "lport":   P_int(default=4444),
          "format":  P_str(default="exe"),
          "output":  P_str(default="/tmp/payload.bin"),
      }, ["payload", "lhost"]),
      argv=["-p", "{{payload}}", "LHOST={{lhost}}", "LPORT={{lport}}",
            "-f", "{{format}}", "-o", "{{output}}"],
      output_artifacts=["{{output}}"]))

add(t("searchsploit_query", "searchsploit", "vuln",
      "Search ExploitDB locally.",
      timeout=120, risk="low",
      args_schema=S({"query": P_str()}, ["query"]),
      argv=["{{query}}"]))

add(t("exploitdb_papers", "searchsploit", "vuln",
      "Search ExploitDB papers (case-sensitive).",
      timeout=120, risk="low",
      args_schema=S({"query": P_str()}, ["query"]),
      argv=["--id", "-c", "{{query}}"]))

add(t("chisel_proxy", "chisel", "post-exploit",
      "Fast TCP/UDP tunnel over HTTP (client/server).",
      timeout=3600, mitre=["T1090"], risk="high",
      args_schema=S({
          "mode": P_enum(["server", "client"], default="server"),
          "args": P_str(default="--reverse"),
      }),
      argv=["{{mode}}", "{{args}}"]))

add(t("ligolo_ng", "ligolo-ng", "post-exploit",
      "Reverse tunneling via TUN interfaces.",
      timeout=3600, mitre=["T1090"], risk="high",
      interactive=True, interaction=PTY_GENERIC,
      args_schema=S({
          "mode": P_enum(["proxy", "agent"], default="proxy"),
          "args": P_str(default="-selfcert"),
      }),
      argv=["{{mode}}", "{{args}}"]))


# ─── SECRETS ──────────────────────────────────────────────────────────────
add(t("trufflehog_scan", "trufflehog", "secrets",
      "High-signal secret scanner across git/filesystem/clouds.",
      timeout=1200, mitre=["T1552.001"], risk="low",
      when="Search a repo or directory for committed credentials/keys.",
      refs=["https://github.com/trufflesecurity/trufflehog"],
      args_schema=S({
          "mode":   P_enum(["git", "filesystem", "github", "s3"], default="filesystem"),
          "source": P_str(),
          "json":   P_bool(default=True),
      }, ["source"]),
      argv=["{{mode}}", "{{source}}", "{{?json}}--json{{/json}}"],
      parser="jsonl"))

add(t("gitleaks_scan", "gitleaks", "secrets",
      "Detect hardcoded secrets in git history.",
      timeout=600, mitre=["T1552.001"], risk="low",
      args_schema=S({
          "source":   P_str(default="."),
          "no_git":   P_bool(default=False),
          "report":   P_str(default="/tmp/gitleaks.json"),
      }),
      argv=["detect", "--source={{source}}",
            "{{?no_git}}--no-git{{/no_git}}",
            "--report-path={{report}}", "--report-format=json"],
      parser="jsonl", output_artifacts=["{{report}}"]))

add(t("detect_secrets_scan", "detect-secrets", "secrets",
      "Yelp's high-signal secret detector.",
      timeout=300, mitre=["T1552.001"], risk="low",
      args_schema=S({"path": P_str(default=".")}),
      argv=["scan", "{{path}}"], parser="jsonl"))


# ─── BLUE TEAM / FORENSICS UTIL ──────────────────────────────────────────
add(t("yara_scan", "yara", "re",
      "Pattern-matching engine for malware identification.",
      timeout=600, mitre=["T1518.001"], risk="low",
      args_schema=S({
          "rules":  P_str(),
          "target": P_str(),
          "recursive": P_bool(default=True),
      }, ["rules", "target"]),
      argv=["{{?recursive}}-r{{/recursive}}", "{{rules}}", "{{target}}"]))

add(t("clamscan_run", "clamscan", "re",
      "ClamAV antivirus scanner.",
      timeout=1800, risk="low",
      args_schema=S({
          "target": P_str(),
          "recursive": P_bool(default=True),
          "infected_only": P_bool(default=True),
      }, ["target"]),
      argv=["{{?recursive}}-r{{/recursive}}",
            "{{?infected_only}}--infected{{/infected_only}}",
            "{{target}}"]))


# ─── MISC / UTILITIES ─────────────────────────────────────────────────────
add(t("curl_request", "curl", "misc",
      "HTTP/HTTPS request tool.",
      timeout=60, risk="low",
      args_schema=S({
          "url":     P_str(),
          "method":  P_enum(["GET", "POST", "PUT", "DELETE", "HEAD"], default="GET"),
          "headers": P_str(default=""),
          "data":    P_str(default=""),
          "verbose": P_bool(default=False),
      }, ["url"]),
      argv=["-X", "{{method}}", "-s",
            "{{?verbose}}-v{{/verbose}}",
            "{{?headers}}-H{{/headers}}", "{{?headers}}{{headers}}{{/headers}}",
            "{{?data}}-d{{/data}}", "{{?data}}{{data}}{{/data}}",
            "{{url}}"], scope_arg="url"))

add(t("wget_fetch", "wget", "misc",
      "Download file from URL.",
      timeout=300, risk="low",
      args_schema=S({
          "url": P_str(),
          "output": P_str(default=""),
      }, ["url"]),
      argv=["{{?output}}-O{{/output}}", "{{?output}}{{output}}{{/output}}",
            "{{url}}"], scope_arg="url"))

add(t("openssl_query", "openssl", "misc",
      "OpenSSL toolkit (s_client, x509, etc.).",
      timeout=60, risk="low",
      args_schema=S({"args": P_str()}, ["args"]),
      argv=["{{args}}"]))

add(t("jq_query", "jq", "misc",
      "JSON query and transformation.",
      timeout=60, risk="low",
      args_schema=S({
          "filter": P_str(default="."),
          "input_file": P_str(),
      }, ["input_file"]),
      argv=["{{filter}}", "{{input_file}}"]))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 8 — Person/Identity OSINT (category: osint)
# ─────────────────────────────────────────────────────────────────────────────
# Every tool in this section targets *identity* (email/username/person/handle)
# rather than network infrastructure. They REQUIRE the engagement to declare
# the corresponding scope_* identity bucket AND a non-empty
# osint_authorization_ref. The osint_server enforces both gates before
# executor.run is ever called. ``pii=True`` flags the audit entry.

add(t("sherlock_run", "sherlock", "osint",
      "Find usernames across 400+ social networks.",
      timeout=900, mitre=["T1589.001"], risk="low", pii=True,
      install_via="pipx",
      when="You need to discover where an authorized username is registered.",
      why="Sherlock checks ~400 sites with regex/HTTP heuristics; passive recon.",
      how="Output goes to stdout; we use --print-found to skip negatives.",
      refs=["https://github.com/sherlock-project/sherlock"],
      args_schema=S({
          "username": P_str(),
          "timeout":  P_int(default=10),
      }, ["username"]),
      argv=["--print-found", "--no-color", "--timeout", "{{timeout}}", "{{username}}"],
      scope_arg="username",
      examples=[{"username": "octocat"}]))

add(t("maigret_run", "maigret", "osint",
      "Deep username OSINT across 3000+ sites with profile parsing.",
      timeout=1800, mitre=["T1589.001"], risk="low", pii=True,
      install_via="pipx",
      when="Need richer profile data than sherlock; willing to wait minutes.",
      refs=["https://github.com/soxoj/maigret"],
      args_schema=S({
          "username": P_str(),
          "timeout":  P_int(default=30),
      }, ["username"]),
      argv=["--no-color", "--timeout", "{{timeout}}", "{{username}}"],
      scope_arg="username",
      parser="raw",
      examples=[{"username": "octocat"}]))

add(t("holehe_run", "holehe", "osint",
      "Check which sites have an account registered with an email.",
      timeout=600, mitre=["T1589.002"], risk="low", pii=True,
      install_via="pipx",
      when="Authorized email → enumerate associated SaaS accounts.",
      refs=["https://github.com/megadose/holehe"],
      args_schema=S({"email": P_str()}, ["email"]),
      argv=["--only-used", "--no-color", "{{email}}"],
      scope_arg="email",
      examples=[{"email": "alice@example.com"}]))

add(t("h8mail_run", "h8mail", "osint",
      "Email breach hunting via free public sources (HIBP scraper, Scylla, etc.).",
      timeout=600, mitre=["T1589.002"], risk="medium", pii=True,
      install_via="pipx",
      when="Authorized email → scan free breach indices for leaked credentials.",
      how=("Without a config file h8mail uses only free sources. To enable "
           "premium APIs (Hunter.io, Snusbase) supply a config and pass it via "
           "config_file."),
      refs=["https://github.com/khast3x/h8mail"],
      args_schema=S({
          "email":       P_str(),
          "config_file": P_str(default=""),
      }, ["email"]),
      argv=["-t", "{{email}}",
            "{{?config_file}}-c{{/config_file}}", "{{?config_file}}{{config_file}}{{/config_file}}"],
      scope_arg="email",
      examples=[{"email": "alice@example.com"}]))

add(t("whatsmyname_run", "whatsmyname", "osint",
      "Username enumeration using the WhatsMyName social-account dataset.",
      timeout=600, mitre=["T1589.001"], risk="low", pii=True,
      install_via="pipx",
      refs=["https://github.com/WebBreacher/WhatsMyName"],
      args_schema=S({"username": P_str()}, ["username"]),
      argv=["-u", "{{username}}"],
      scope_arg="username",
      examples=[{"username": "octocat"}]))

add(t("recon_ng_batch", "recon-ng", "osint",
      "Run a batch recon-ng workspace with a curated module set (passive).",
      timeout=900, mitre=["T1589", "T1590"], risk="low", pii=True,
      install_via="pipx",
      when="Need a multi-module passive recon snapshot; non-interactive.",
      how=("Wrapper: writes a temporary recon-ng resource file that loads the "
           "passive modules listed in `modules` and runs them against `target`."),
      refs=["https://github.com/lanmaster53/recon-ng"],
      args_schema=S({
          "target":   P_str(),
          "kind":     P_enum(["domain", "email", "person", "username"], default="domain"),
          "modules":  P_str(default="recon/domains-hosts/hackertarget"),
      }, ["target"]),
      # The osint_server builds the resource file and passes -r <path>; the
      # template here is what the executor sees AFTER server-side rendering.
      argv=["-r", "{{target}}"],  # placeholder; osint_server overrides with -r <resource_path>
      scope_arg=None,  # scope is enforced by osint_server based on `kind`
      examples=[{"target": "octocat", "kind": "username"}]))

add(t("spiderfoot_batch", "sf", "osint",
      "Run a SpiderFoot CLI scan with a curated module set.",
      timeout=1800, mitre=["T1589", "T1590"], risk="medium", pii=True,
      install_via="pipx",
      when="Comprehensive passive OSINT aggregation across 200+ modules.",
      how=("Uses `sf -s <target> -m <modules> -F json`. Defaults to a passive "
           "module subset to avoid active probing."),
      refs=["https://github.com/smicallef/spiderfoot"],
      args_schema=S({
          "target":   P_str(),
          "kind":     P_enum(["domain", "email", "person", "username"], default="email"),
          "modules":  P_str(default="sfp_dnsresolve,sfp_email,sfp_hunter,sfp_haveibeenpwned"),
      }, ["target"]),
      argv=["-s", "{{target}}", "-m", "{{modules}}", "-F", "json", "-q"],
      scope_arg=None,  # enforced by osint_server based on `kind`
      examples=[{"target": "alice@example.com", "kind": "email"}]))

add(t("social_analyzer_run", "social-analyzer", "osint",
      "Analyze and find a person/username across social media.",
      timeout=900, mitre=["T1589.001"], risk="low", pii=True,
      install_via="pipx",
      refs=["https://github.com/qeeqbox/social-analyzer"],
      args_schema=S({
          "username": P_str(),
          "top":      P_int(default=100),
      }, ["username"]),
      argv=["--cli", "--username", "{{username}}", "--top", "{{top}}",
            "--output", "json", "--silent"],
      scope_arg="username",
      examples=[{"username": "octocat"}]))

add(t("ghunt_email", "ghunt", "osint",
      "GHunt: Google account intel from an email (Gaia ID, profile, services).",
      timeout=600, mitre=["T1589.002"], risk="low", pii=True,
      install_via="pipx", requires_manual_setup=True,
      when="Authorized email → recover linked Google profile metadata.",
      how=("REQUIRES one-time cookie setup: `ghunt login` and follow prompts to "
           "store creds in ~/.malfrats/ghunt/. Tool refuses to run without it."),
      refs=["https://github.com/mxrch/GHunt"],
      args_schema=S({"email": P_str()}, ["email"]),
      argv=["email", "{{email}}", "--json", "/dev/stdout"],
      scope_arg="email",
      examples=[{"email": "alice@example.com"}]))


# ─────────────────────────────────────────────────────────────────────────────
# Emit YAML
# ─────────────────────────────────────────────────────────────────────────────

HEADER = """# parrot_tools.yaml — Declarative catalogue of Parrot OS offensive tools.
#
# Generated by scripts/build_catalog.py — DO NOT EDIT BY HAND.
# To add or modify a tool, edit the generator and rerun:
#     python3 scripts/build_catalog.py
#
# Schema (per entry):
#   name:                  short identifier exposed to the agent
#   binary:                resolved by `command -v` at runtime
#   category:              recon | web | vuln | ad | creds | network |
#                          wireless | re | secrets | cloud | mobile |
#                          iot | post-exploit | osint | misc
#   description:           one-line summary
#   requires_sudo:         bool
#   sudo_reason:           string shown in approval modal
#   default_timeout_seconds: int
#   mitre:                 list of ATT&CK technique IDs
#   risk_level:            low | medium | high | critical
#   interactive:           bool — if true, use parrot_session_* tools
#   interaction:           { type, prompts, commands_help } when interactive
#   when / why / how_notes:Markdown helpers shown to the LLM
#   references:            list of URLs
#   args_schema:           JSON-Schema-compatible object validated at call time
#   argv_template:         list of strings; {{name}} placeholders are
#                          shlex-quoted, {{?name}}…{{/name}} is conditional
#   scope_arg:             which arg key feeds the ScopeValidator
#   parser:                raw | jsonl | xml | nmap_xml | csv
#   examples:              list of minimal example arg dicts
#   output_artifacts:      filesystem paths the tool may produce
#

"""


def main() -> int:
    if OUT.exists():
        shutil.copy2(OUT, BAK)

    # Group by category for readability of the emitted file.
    cats_order = [
        "recon", "osint", "web", "vuln", "ad", "creds", "network",
        "wireless", "re", "secrets", "cloud", "mobile",
        "iot", "post-exploit", "misc",
    ]
    grouped: dict[str, list[dict]] = {c: [] for c in cats_order}
    for d in TOOLS:
        grouped.setdefault(d["category"], []).append(d)

    out_text = HEADER
    for c in cats_order:
        bucket = grouped.get(c, [])
        if not bucket:
            continue
        out_text += f"# ─── {c.upper()} " + "─" * (70 - len(c)) + "\n\n"
        for d in bucket:
            chunk = yaml.safe_dump(
                [d], sort_keys=False, allow_unicode=True,
                default_flow_style=False, width=100,
            )
            out_text += chunk + "\n"

    OUT.write_text(out_text)

    # Validate by re-loading
    parsed = yaml.safe_load(OUT.read_text())
    print(f"[build_catalog] wrote {len(parsed)} tool descriptors → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
