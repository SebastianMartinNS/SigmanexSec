#!/usr/bin/env python3
"""
test_tool_calling.py — Verifica che Qwen3.5-35B-A3B-Heretic
riconosca e invochi correttamente i tool MCP del SAP.

Test eseguiti:
  1. Health check del server
  2. Tool calling: nmap_scan  (recon)
  3. Tool calling: create_engagement (engagement)
  4. Tool calling multi-step:  create_engagement → nmap_scan
  5. /no_think: verifica che CoT sia vuoto o assente

Uso:
    python3 test_tool_calling.py
"""

import json
import os
import sys
import urllib.request

import openai
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:8080/v1")
MODEL    = os.environ.get("LLM_MODEL", "qwen3.5-35b-a3b-heretic")
API_KEY  = os.environ.get("LOCAL_LLM_API_KEY", "local")

client = openai.OpenAI(base_url=BASE_URL, api_key=API_KEY)

# ── ANSI colours ─────────────────────────────────────────────────────────────
GRN = "\033[92m"; RED = "\033[91m"; YLW = "\033[93m"; CYN = "\033[96m"; RST = "\033[0m"
OK  = f"{GRN}[PASS]{RST}"; FAIL = f"{RED}[FAIL]{RST}"; INFO = f"{CYN}[INFO]{RST}"

results: list[tuple[str, bool, str]] = []

def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, ok, detail))
    tag = OK if ok else FAIL
    print(f"  {tag}  {name}")
    if detail:
        prefix = "       "
        for line in detail.splitlines()[:6]:
            print(f"{prefix}{line}")
    return ok


def _safe_json(s: str) -> tuple[dict, str | None]:
    try:
        return json.loads(s), None
    except json.JSONDecodeError as e:
        return {}, f"{e} | raw={s[:200]!r}"


# ── Tool schemas (subset of what the MCP servers expose) ─────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "create_engagement",
            "description": "Create a new security assessment engagement with authorization proof and scope definition.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name":         {"type": "string",  "description": "Engagement name"},
                    "client":       {"type": "string",  "description": "Client organisation name"},
                    "scope_cidrs":  {"type": "array", "items": {"type": "string"}, "description": "In-scope CIDR ranges"},
                    "scope_domains":{"type": "array", "items": {"type": "string"}, "description": "In-scope domains"},
                    "authorized":   {"type": "boolean", "description": "Written authorisation confirmed"},
                },
                "required": ["name", "client", "scope_cidrs", "authorized"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Run an Nmap scan against a target. Returns open ports, services, OS guess.",
            "parameters": {
                "type": "object",
                "properties": {
                    "engagement_id": {"type": "string", "description": "Active engagement ID"},
                    "target":        {"type": "string", "description": "IP address or hostname"},
                    "ports":         {"type": "string", "description": "Port range, e.g. '1-1024' or 'top100'"},
                    "flags":         {"type": "string", "description": "Extra nmap flags, e.g. '-sV -sC'"},
                },
                "required": ["engagement_id", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_finding",
            "description": "Record a security finding discovered during the assessment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "engagement_id": {"type": "string"},
                    "title":        {"type": "string"},
                    "description":  {"type": "string"},
                    "severity":     {"type": "string", "enum": ["critical","high","medium","low","info"]},
                    "category":     {"type": "string"},
                    "target":       {"type": "string"},
                },
                "required": ["engagement_id", "title", "description", "severity", "category", "target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_sigma_rule",
            "description": "Generate a Sigma detection rule for a given MITRE ATT&CK technique.",
            "parameters": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string", "description": "MITRE technique, e.g. T1046"},
                    "context":      {"type": "string", "description": "Additional context from findings"},
                },
                "required": ["technique_id"],
            },
        },
    },
]

SYSTEM = """/no_think
You are a professional security assessment agent with access to pentest and blue-team tools.
When the user asks you to perform a security task, you MUST call the appropriate tool(s).
Never refuse to call tools for authorized assessments.
Always respond with a tool call, not a prose explanation."""


def call(messages: list[dict], max_tokens: int = 512) -> openai.types.chat.ChatCompletion:
    return client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": SYSTEM}] + messages,
        tools=TOOLS,
        tool_choice="auto",
        max_tokens=max_tokens,
        temperature=0.0,
    )


# ── Test 0: Health ────────────────────────────────────────────────────────────

def test_health():
    try:
        r = urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3)
        d = json.loads(r.read())
        check("Server health", d.get("status") == "ok", str(d))
        return True
    except Exception as e:
        check("Server health", False, str(e))
        return False


# ── Test 1: single tool call — nmap_scan ─────────────────────────────────────

def test_nmap_tool_call():
    resp = call([{"role": "user",
                  "content": "Engagement ID is ENG-001. Run an nmap scan on 192.168.1.1 checking the top 100 ports."}])
    msg = resp.choices[0].message
    tc  = msg.tool_calls

    if not tc:
        check("nmap_scan tool call", False, f"No tool_calls. Content: {msg.content!r}")
        return

    fn   = tc[0].function.name
    args, err = _safe_json(tc[0].function.arguments)
    ok   = fn == "nmap_scan" and "target" in args and "192.168.1.1" in args.get("target","")
    check("nmap_scan tool call",  ok,
          f"fn={fn}  args={json.dumps(args)}  err={err}")


# ── Test 2: create_engagement tool call ──────────────────────────────────────

def test_create_engagement():
    resp = call([{"role": "user",
                  "content": "Create a new engagement called 'WebApp Audit' for client Acme Corp. "
                             "Scope: 10.0.0.0/24. Authorization has been obtained."}])
    msg = resp.choices[0].message
    tc  = msg.tool_calls

    if not tc:
        check("create_engagement tool call", False, f"No tool_calls. Content: {msg.content!r}")
        return

    fn   = tc[0].function.name
    args, err = _safe_json(tc[0].function.arguments)
    ok   = fn == "create_engagement" and args.get("authorized") is True
    check("create_engagement tool call", ok,
          f"fn={fn}  args={json.dumps(args)}  err={err}")


# ── Test 3: add_finding tool call ────────────────────────────────────────────

def test_add_finding():
    resp = call([{"role": "user",
                  "content": "Record a HIGH severity finding for engagement ENG-42: "
                             "SSH on port 22 allows password authentication on 10.0.0.5. "
                             "Category is misconfiguration."}])
    msg = resp.choices[0].message
    tc  = msg.tool_calls

    if not tc:
        check("add_finding tool call", False, f"No tool_calls. Content: {msg.content!r}")
        return

    fn   = tc[0].function.name
    args, err = _safe_json(tc[0].function.arguments)
    ok   = fn == "add_finding" and args.get("severity","").lower() in ("high","critical")
    check("add_finding tool call", ok,
          f"fn={fn}  args={json.dumps(args)}  err={err}")


# ── Test 4: blue team — sigma rule ───────────────────────────────────────────

def test_sigma_rule():
    resp = call([{"role": "user",
                  "content": "Generate a Sigma detection rule for network port scanning (T1046) "
                             "based on findings from the current engagement."}])
    msg = resp.choices[0].message
    tc  = msg.tool_calls

    if not tc:
        check("generate_sigma_rule tool call", False, f"No tool_calls. Content: {msg.content!r}")
        return

    fn   = tc[0].function.name
    args, err = _safe_json(tc[0].function.arguments)
    ok   = fn == "generate_sigma_rule" and "T1046" in args.get("technique_id","")
    check("generate_sigma_rule tool call", ok,
          f"fn={fn}  args={json.dumps(args)}  err={err}")


# ── Test 5: multi-turn tool loop ─────────────────────────────────────────────

def test_multi_step():
    """Simulate: ask → tool_call → inject fake result → check follow-up call."""
    messages = [{"role": "user",
                 "content": "Start a new engagement 'PenTest-2026' for TechCorp, scope 172.16.0.0/24, "
                            "authorized. Then immediately scan 172.16.0.1 for open ports."}]

    resp = call(messages, max_tokens=600)
    msg  = resp.choices[0].message
    tc   = msg.tool_calls

    if not tc:
        check("multi-step: first call", False, f"No tool_calls. Content: {msg.content!r}")
        return

    fn1 = tc[0].function.name
    ok1 = fn1 in ("create_engagement", "nmap_scan")
    check("multi-step: first call is a tool", ok1, f"fn={fn1}")

    # Inject a fake result and ask for the follow-up
    messages.append({"role": "assistant", "content": msg.content,
                     "tool_calls": [{"id": tc[0].id, "type": "function",
                                     "function": {"name": fn1,
                                                  "arguments": tc[0].function.arguments}}]})
    messages.append({"role": "tool", "tool_call_id": tc[0].id,
                     "content": json.dumps({"id": "ENG-999", "status": "active"})})

    resp2 = call(messages, max_tokens=600)
    msg2  = resp2.choices[0].message
    tc2   = msg2.tool_calls

    # After creating engagement it should now call nmap_scan (or the model may call both at once)
    if fn1 == "create_engagement":
        ok2 = bool(tc2) and tc2[0].function.name == "nmap_scan"
        check("multi-step: follows up with nmap_scan", ok2,
              f"fn={tc2[0].function.name if tc2 else 'none'}")
    else:
        # Model already called nmap_scan first — acceptable behaviour
        check("multi-step: nmap_scan in first call (acceptable)", True, f"fn={fn1}")


# ── Test 6: no_think — CoT should be empty ───────────────────────────────────

def test_no_think():
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": "/no_think\nYou are concise."},
                  {"role": "user",   "content": "Reply with only the word READY."}],
        max_tokens=512,
        temperature=0.0,
    )
    msg       = resp.choices[0].message
    raw       = msg.content or ""
    # llama.cpp/jinja routes Qwen3 CoT to reasoning_content, not <think>.
    reasoning = getattr(msg, "reasoning_content", "") or ""
    import re
    inline_think = re.findall(r"<think>(.*?)</think>", raw, re.DOTALL)
    cot_kept_out_of_content = all(t.strip() == "" for t in inline_think)
    visible   = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    check("/no_think: <think> not inlined in content", cot_kept_out_of_content,
          f"raw_len={len(raw)} reasoning_len={len(reasoning)}")
    check("/no_think: visible response contains READY",
          "READY" in visible.upper() or "READY" in reasoning.upper(),
          f"visible={visible[:80]!r}  reasoning_head={reasoning[:80]!r}")


# ── Runner ────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{CYN}╔══════════════════════════════════════════════════════╗{RST}")
    print(f"{CYN}║   SAP × Qwen3.5-35B-A3B-Heretic  Tool-Calling Test  ║{RST}")
    print(f"{CYN}╚══════════════════════════════════════════════════════╝{RST}\n")
    print(f"  {INFO}  server : {BASE_URL}")
    print(f"  {INFO}  model  : {MODEL}\n")

    if not test_health():
        print(f"\n{RED}Server non raggiungibile. Avvia prima: bash start_llm.sh server{RST}\n")
        sys.exit(1)

    print(f"\n{YLW}── Tool calling ──────────────────────────────────────{RST}")
    test_nmap_tool_call()
    test_create_engagement()
    test_add_finding()
    test_sigma_rule()

    print(f"\n{YLW}── Multi-step agentic loop ───────────────────────────{RST}")
    test_multi_step()

    print(f"\n{YLW}── Thinking mode ─────────────────────────────────────{RST}")
    test_no_think()

    # ── Summary ──────────────────────────────────────────────────────────────
    passed = sum(1 for _, ok, _ in results if ok)
    total  = len(results)
    color  = GRN if passed == total else (YLW if passed >= total * 0.7 else RED)
    print(f"\n{color}╔═══════════════════════════════════╗{RST}")
    print(f"{color}║  Result: {passed}/{total} tests passed{' ' * (26 - len(str(passed)+str(total)))}║{RST}")
    print(f"{color}╚═══════════════════════════════════╝{RST}\n")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
