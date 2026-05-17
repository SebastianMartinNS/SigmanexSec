#!/usr/bin/env python3
"""
test_mcp_tool_calling.py — End-to-end test dei 37 tool MCP via llama-server.

1) Enumera gli schema dai 4 server MCP (streamable-http).
2) Li registra nel modello come tools OpenAI-style su /v1/chat/completions.
3) Per ogni scenario verifica: (a) il modello sceglie il tool giusto,
   (b) gli argomenti sono JSON validi secondo l'inputSchema MCP.
"""
from __future__ import annotations

import asyncio
import json
import sys

import requests
from jsonschema import Draft202012Validator
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

LLM   = "http://127.0.0.1:8080/v1/chat/completions"
MODEL = "qwen3.5-35b-a3b-heretic"

SERVERS = {
    "engagement": "http://127.0.0.1:9001/mcp",
    "recon":      "http://127.0.0.1:9002/mcp",
    "exploit":    "http://127.0.0.1:9003/mcp",
    "blueteam":   "http://127.0.0.1:9004/mcp",
}

# (prompt, expected_tool_name, required_args_subset)
SCENARIOS = [
    ("Create an engagement named 'WebApp-2026' for client 'Acme Corp', tester 'pentester-1', "
     "authorization reference AUTH-2026-001, scope CIDR 10.0.0.0/24 and domain acme.test.",
     "create_engagement",
     {"name": "WebApp-2026", "client": "Acme Corp", "tester": "pentester-1",
      "authorization_ref": "AUTH-2026-001"}),

    ("Engagement ENG-77 is active. Run an nmap scan on 10.0.0.5 for top 100 ports with -sV.",
     "nmap_scan",
     {"engagement_id": "ENG-77", "target": "10.0.0.5"}),

    ("For engagement ENG-77 run a masscan on 10.0.0.0/24 for ports 1-65535.",
     "masscan_scan",
     {"engagement_id": "ENG-77"}),

    ("For engagement ENG-77 enumerate DNS for domain acme.test.",
     "dns_recon",
     {"engagement_id": "ENG-77", "domain": "acme.test"}),

    ("For engagement ENG-77 fingerprint the web stack of https://acme.test.",
     "web_fingerprint",
     {"engagement_id": "ENG-77"}),

    ("For engagement ENG-77 detect WAF on https://acme.test.",
     "waf_detect",
     {"engagement_id": "ENG-77"}),

    ("For engagement ENG-77 directory-fuzz https://acme.test/ with a common wordlist.",
     "dir_fuzz",
     {"engagement_id": "ENG-77"}),

    ("Enumerate SMB shares on 10.0.0.10 for engagement ENG-77.",
     "smb_enum",
     {"engagement_id": "ENG-77", "target": "10.0.0.10"}),

    ("Test the URL https://acme.test/login?id=1 for SQL injection (engagement ENG-77).",
     "sqli_test",
     {"engagement_id": "ENG-77"}),

    ("Identify the hash type of: 5f4dcc3b5aa765d61d8327deb882cf99",
     "identify_hash",
     {"hash_value": "5f4dcc3b5aa765d61d8327deb882cf99"}),

    ("Crack this MD5 hash 5f4dcc3b5aa765d61d8327deb882cf99 with rockyou wordlist (engagement ENG-77).",
     "crack_hash",
     {"engagement_id": "ENG-77"}),

    ("Record a high-severity finding for engagement ENG-77: 'SSH allows password auth' on 10.0.0.5, "
     "category misconfiguration.",
     "add_finding",
     {"engagement_id": "ENG-77", "severity": "high", "category": "misconfiguration"}),

    ("List all findings for engagement ENG-77.",
     "get_findings",
     {"engagement_id": "ENG-77"}),

    ("Move engagement ENG-77 into the exploitation phase.",
     "set_phase",
     {"engagement_id": "ENG-77"}),

    ("For engagement ENG-77, generate a Sigma rule for MITRE technique T1046 (network service scanning).",
     "generate_sigma_rule",
     {"engagement_id": "ENG-77", "technique_id": "T1046"}),

    ("For engagement ENG-77, generate firewall rules from the hosts JSON '[]' (empty host list) "
     "to harden the perimeter.",
     "generate_firewall_rules",
     {"engagement_id": "ENG-77"}),

    ("Produce an incident response playbook for MITRE technique T1486 (ransomware on Windows endpoints).",
     "generate_ir_playbook",
     {"technique_id": "T1486"}),

    ("Generate the final assessment report for engagement ENG-77.",
     "generate_assessment_report",
     {"engagement_id": "ENG-77"}),
]


async def collect_tools() -> tuple[list[dict], dict[str, dict]]:
    openai_tools: list[dict] = []
    schemas: dict[str, dict] = {}
    for _name, url in SERVERS.items():
        async with streamablehttp_client(url) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tl = await s.list_tools()
                for t in tl.tools:
                    openai_tools.append({
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": (t.description or "")[:500],
                            "parameters": t.inputSchema,
                        },
                    })
                    schemas[t.name] = t.inputSchema
    return openai_tools, schemas


def ask(tools: list[dict], prompt: str) -> dict:
    body = {
        "model": MODEL,
        "temperature": 0,
        "max_tokens": 512,
        "tools": tools,
        "tool_choice": "auto",
        "messages": [
            {"role": "system",
             "content": "You are a pentest orchestrator. Always call exactly ONE tool that "
                        "matches the user request, with concrete arguments. /no_think"},
            {"role": "user", "content": prompt},
        ],
    }
    r = requests.post(LLM, json=body, timeout=180)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]


def check(msg: dict, expected_tool: str, required: dict, schema: dict) -> tuple[bool, str]:
    calls = msg.get("tool_calls") or []
    if not calls:
        return False, f"no tool_calls (content={str(msg.get('content'))[:120]!r})"
    call = calls[0]["function"]
    if call["name"] != expected_tool:
        return False, f"expected '{expected_tool}', got '{call['name']}'"
    try:
        args = json.loads(call["arguments"])
    except Exception as e:
        return False, f"arguments not JSON: {e}"
    # validate against MCP input schema
    try:
        Draft202012Validator(schema).validate(args)
    except Exception as e:
        return False, f"schema violation: {str(e).splitlines()[0]}"
    # required subset
    for k, v in required.items():
        if k not in args:
            return False, f"missing arg '{k}' in {list(args)}"
        if isinstance(v, str) and v.lower() not in str(args[k]).lower():
            return False, f"arg '{k}'={args[k]!r} should contain {v!r}"
        if isinstance(v, bool) and bool(args[k]) != v:
            return False, f"arg '{k}'={args[k]!r} should be {v}"
    return True, f"args={json.dumps(args, ensure_ascii=False)[:140]}"


async def main():
    print("Collecting MCP schemas...")
    tools, schemas = await collect_tools()
    print(f"Registered {len(tools)} tools in the model\n")

    passed = failed = 0
    details = []
    for i, (prompt, want, required) in enumerate(SCENARIOS, 1):
        try:
            msg = ask(tools, prompt)
            ok, info = check(msg, want, required, schemas[want])
        except Exception as e:
            ok, info = False, f"exception: {e}"
        tag = "PASS" if ok else "FAIL"
        print(f"[{tag}] {i:2d}/{len(SCENARIOS)}  {want:<30} :: {info}")
        details.append((ok, want, prompt, info))
        passed += ok; failed += not ok

    print(f"\nResult: {passed}/{len(SCENARIOS)} scenarios PASS, {failed} FAIL")
    if failed:
        print("\nFailures:")
        for ok, want, prompt, info in details:
            if not ok:
                print(f"  - {want}: {info}\n    prompt: {prompt!r}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
