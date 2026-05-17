"""
agent/orchestrator.py — LLM Agent Orchestrator.

Connects to all MCP servers, exposes their tools to the LLM,
and runs the agentic loop: think → call tool → observe → repeat.

Supports:
  - Anthropic Claude (default)
  - OpenAI GPT-4o

Usage:
    orchestrator = Orchestrator()
    await orchestrator.run(
        engagement_id="<id>",
        objective="Find all vulnerabilities on 10.0.0.0/24",
    )
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from dotenv import load_dotenv

load_dotenv()

from agent.run_modes import Plan, RunMode
from core.approval_gate import ApprovalGate, AutoApproveGate
from core.llm_io_sanitizer import sanitize_tool_output
from core.memory import MemoryManager, builtin_tool_specs
from core.memory.tools import dispatch_builtin_tool

_MEMORY_ENABLED = os.environ.get("SAP_MEMORY_ENABLED", "1").lower() not in ("0", "false", "no", "off")


# ── MCP Client imports ────────────────────────────────────────────────────────
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# ── LLM Client ───────────────────────────────────────────────────────────────
_PROVIDER      = os.environ.get("LLM_PROVIDER", "local").lower()
_MODEL         = os.environ.get("LLM_MODEL", "qwen3-30b-a3b-q4")
# For local / openai-compatible backends
_LOCAL_BASE_URL = os.environ.get("LOCAL_LLM_BASE_URL", "http://localhost:8080/v1")
# Think mode: "think" enables CoT, "no_think" keeps responses concise.
# Qwen3 respects /no_think and /think control tokens in system prompt.
_THINK_MODE     = os.environ.get("LOCAL_THINK_MODE", "no_think")
# Per-turn completion budget. Must be large enough to emit a full tool_call
# JSON plus the eventual natural-language summary (Qwen3 can be verbose in
# reasoning_content even under /no_think).
_MAX_TOKENS     = int(os.environ.get("LLM_MAX_TOKENS", "4096"))
# Hard cap on the size of a tool result emitted to the on_message callback
# (dashboard / WebSocket). The full result is still fed back into the LLM
# context and persisted in the audit log.
def _load_orchestrator_cfg() -> dict:
    p = Path(__file__).parent.parent / "config.yaml"
    if not p.exists():
        return {}
    try:
        import yaml as _yaml
        with open(p) as f:
            return _yaml.safe_load(f) or {}
    except Exception:
        return {}

_ORCH_CFG = _load_orchestrator_cfg()
_CALLBACK_RESULT_CAP = int(
    os.environ.get(
        "SAP_CALLBACK_RESULT_CAP",
        str(_ORCH_CFG.get("agent", {}).get("callback_result_cap", 16384)),
    )
)
# Head/tail split for smart truncation: keep both ends so JSON payloads with
# important trailing fields (returncode, summary) are not lost.
_CALLBACK_HEAD_FRACTION = float(
    _ORCH_CFG.get("agent", {}).get("callback_head_fraction", 0.75)
)
# Circuit breaker: abort the loop if the same (tool, args) tuple is invoked
# this many times in a single run — protects against pathological loops.
_TOOL_LOOP_LIMIT = int(os.environ.get("SAP_TOOL_LOOP_LIMIT", "3"))
# Hard timeout per LLM completion call. Without this, a stalled llama.cpp
# inference (e.g. context-window blow-up around iter 5-6) freezes the whole
# event loop and the run appears "stuck after tool result". Default 240s.
_LLM_REQUEST_TIMEOUT = float(os.environ.get("SAP_LLM_REQUEST_TIMEOUT", "240"))

# Pre-flight prompt-token budget (defence-in-depth — see plan 2026-04-30).
# llama-server's n_ctx_slot is 200 704 by default; staying safely below
# leaves room for the model's own output tokens and tool schemas.
_PROMPT_TOKEN_BUDGET = int(
    os.environ.get(
        "SAP_PROMPT_TOKEN_BUDGET",
        str(_ORCH_CFG.get("agent", {}).get("prompt_token_budget", 170_000)),
    )
)
# Soft warning threshold (tokens). Above this we emit a token_budget event
# every iteration so the dashboard shows the trend before we hit the hard
# budget. 0 disables the warning.
_PROMPT_TOKEN_WARN = int(
    os.environ.get(
        "SAP_PROMPT_TOKEN_WARN",
        str(_ORCH_CFG.get("agent", {}).get("prompt_token_warn", 50_000)),
    )
)

import openai as _openai_lib

if _PROVIDER == "anthropic":
    import anthropic
    _llm = anthropic.Anthropic(
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        timeout=_LLM_REQUEST_TIMEOUT,
    )
elif _PROVIDER in ("openai", "local"):
    # Both cloud OpenAI and any local OpenAI-compatible server (llama.cpp,
    # Ollama /v1, LM Studio, koboldcpp, etc.) use the same client.
    _base_url = None if _PROVIDER == "openai" else _LOCAL_BASE_URL
    _api_key  = (
        os.environ.get("OPENAI_API_KEY", "sk-no-key")
        if _PROVIDER == "openai"
        else os.environ.get("LOCAL_LLM_API_KEY", "local")
    )
    _llm_oai = _openai_lib.OpenAI(
        base_url=_base_url, api_key=_api_key, timeout=_LLM_REQUEST_TIMEOUT,
    )
else:
    raise RuntimeError(f"Unsupported LLM_PROVIDER: {_PROVIDER!r}")


def _strip_thinking(text: str) -> tuple[str, str]:
    """
    Qwen3 may wrap its chain-of-thought in <think>...</think> tags.
    Returns (visible_text, thinking_text).
    The thinking is separated so the agentic loop only sees the
    actual answer/tool-call decision, keeping context clean.
    """
    import re
    thinking_parts = re.findall(r"<think>(.*?)</think>", text, re.DOTALL)
    visible = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    return visible, "\n".join(thinking_parts).strip()


# ── System prompt ─────────────────────────────────────────────────────────────
PROMPTS_DIR = Path(__file__).parent / "prompts"
_SYSTEM_PROMPT_PATH = PROMPTS_DIR / "system_prompt.md"
SYSTEM_PROMPT = (
    _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    if _SYSTEM_PROMPT_PATH.exists()
    else "You are a professional security assessment assistant."
)


def _mode_prompt(mode: RunMode) -> str:
    p = PROMPTS_DIR / f"mode_{mode.value}.md"
    return p.read_text(encoding="utf-8") if p.exists() else ""


# ── MCP Server definitions ────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).parent.parent
_SERVERS = {
    "engagement": _REPO_ROOT / "mcp_servers" / "engagement_server.py",
    "recon":      _REPO_ROOT / "mcp_servers" / "recon_server.py",
    "exploit":    _REPO_ROOT / "mcp_servers" / "exploit_server.py",
    "blueteam":   _REPO_ROOT / "mcp_servers" / "blueteam_server.py",
    "parrot":     _REPO_ROOT / "mcp_servers" / "parrot_server.py",
}


# ── Tool registry ─────────────────────────────────────────────────────────────

class ToolRegistry:
    """Collects tools from all MCP servers and dispatches calls."""

    def __init__(self):
        self._sessions: dict[str, ClientSession] = {}
        self._tool_to_server: dict[str, str] = {}
        self._tools: list[dict] = []
        self._contexts: list[Any] = []

    def register_builtin(self, specs: list[dict]) -> None:
        """Register in-process tools (memory layer) alongside MCP-discovered ones."""
        for spec in specs:
            if spec["name"] in self._tool_to_server:
                continue
            self._tool_to_server[spec["name"]] = "__builtin__"
            self._tools.append({
                "name": spec["name"],
                "description": spec.get("description", ""),
                "input_schema": spec.get("input_schema", {"type": "object", "properties": {}}),
            })

    def is_builtin(self, name: str) -> bool:
        return self._tool_to_server.get(name) == "__builtin__"

    async def build(self) -> None:
        """Start all MCP server subprocesses and collect their tools."""
        python = sys.executable

        for server_name, server_path in _SERVERS.items():
            if not server_path.exists():
                print(f"[WARN] Server script not found: {server_path}", flush=True)
                continue

            params = StdioServerParameters(
                command=python,
                args=[str(server_path)],
                env={**os.environ, "PYTHONPATH": str(_REPO_ROOT)},
            )
            ctx = stdio_client(params)
            read, write = await ctx.__aenter__()
            session = ClientSession(read, write)
            await session.__aenter__()
            await session.initialize()
            self._contexts.append((ctx, session))
            self._sessions[server_name] = session

            # Harvest tools
            tools_result = await session.list_tools()
            for tool in tools_result.tools:
                self._tool_to_server[tool.name] = server_name
                # inputSchema from list_tools() is the correct MCP-generated schema.
                # It matches tool.parameters (Pydantic-derived) on the server side.
                self._tools.append({
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": tool.inputSchema or {
                        "type": "object", "properties": {}
                    },
                })

        print(
            f"[+] Loaded {len(self._tools)} tools from {len(self._sessions)} MCP servers.",
            flush=True
        )

    async def call(self, tool_name: str, tool_input: dict) -> str:
        server_name = self._tool_to_server.get(tool_name)
        if not server_name:
            return json.dumps({"error": f"Tool '{tool_name}' not found."})
        if server_name == "__builtin__":
            # Builtin tools are dispatched by the orchestrator itself.
            return json.dumps({"error": "builtin tool must be dispatched by orchestrator"})
        session = self._sessions[server_name]
        result = await session.call_tool(tool_name, tool_input)
        if hasattr(result, "content") and result.content:
            parts = []
            for content in result.content:
                if hasattr(content, "text"):
                    parts.append(content.text)
            return "\n".join(parts)
        return str(result)

    async def close(self) -> None:
        for ctx, session in self._contexts:
            try:
                await session.__aexit__(None, None, None)
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass

    def anthropic_tools(self) -> list[dict]:
        """Return tools in Anthropic API format."""
        return [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            }
            for t in self._tools
        ]

    def openai_tools(self) -> list[dict]:
        """Return tools in OpenAI API format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in self._tools
        ]


# ── Agentic loop ──────────────────────────────────────────────────────────────

class Orchestrator:
    """
    The main LLM agent loop.

    Runs until the LLM produces a final answer (no more tool calls)
    or max_iterations is reached.
    """

    MAX_ITERATIONS = 50

    def __init__(
        self,
        on_message=None,
        mode: RunMode = RunMode.EXECUTION,
        approval_gate: ApprovalGate | None = None,
        run_id: str | None = None,
        audit_log=None,
    ):
        self._registry = ToolRegistry()
        self._on_message = on_message or (lambda role, text: print(f"\n[{role}] {text}", flush=True))
        self._mode = mode
        self._gate = approval_gate or (AutoApproveGate() if mode is not RunMode.STEP else ApprovalGate())
        self._run_id = run_id or f"run_{uuid.uuid4().hex[:12]}"
        self._plan: Plan | None = None
        self._last_thinking: str = ""
        self._tool_call_counts: Counter = Counter()
        self._memory: MemoryManager | None = None
        self._engagement_id: str = ""
        # Optional audit log used by the adaptive layer to emit structured
        # decision events (DecisionKind). Wiring is opt-in to keep the
        # default constructor signature stable for existing callers.
        self._audit_log = audit_log
        # Adaptive runtime state — populated by _run_adaptive_classification
        # at the start of every run. Always present so phase-4 helpers can
        # short-circuit cheaply when the adaptive layer is disabled.
        self._adaptive_settings = None  # type: ignore[assignment]
        self._adaptive_playbook = None  # type: ignore[assignment]
        self._adaptive_scenario = None  # type: ignore[assignment]
        self._repetition_handler = None  # type: ignore[assignment]

    @staticmethod
    def _truncate_for_callback(text: str) -> str:
        if text is None:
            return ""
        n = len(text)
        if n <= _CALLBACK_RESULT_CAP:
            return text
        # Smart head+tail split — preserves leading context and trailing
        # status/summary fields that head-only truncation would lose.
        head_len = max(1, int(_CALLBACK_RESULT_CAP * _CALLBACK_HEAD_FRACTION))
        tail_len = max(0, _CALLBACK_RESULT_CAP - head_len)
        omitted = n - head_len - tail_len
        # Try to hint at the canonical persisted output URI when present.
        ref_hint = ""
        try:
            import re as _re
            m = _re.search(r'"stdout_uri"\s*:\s*"(sap://[^"]+)"', text)
            if m:
                ref_hint = f"; full output: {m.group(1)}"
        except Exception:
            ref_hint = ""
        marker = f"\n... [truncated {omitted} chars{ref_hint}] ...\n"
        if tail_len <= 0:
            return text[:head_len] + marker
        return text[:head_len] + marker + text[-tail_len:]

    # ── Pre-flight prompt budget (defence-in-depth) ────────────────────────
    # See ROOT-CAUSE plan 2026-04-30: prevents the orchestrator from POSTing
    # a >n_ctx prompt to llama-server (which now triggers HTTP 400). The
    # guard runs before every messages.create / chat.completions.create.

    @staticmethod
    def _measure_prompt(messages: list, *, system_text: str = "", tools: list | None = None) -> int:
        """Approximate total prompt tokens for the next LLM call.

        Mirrors what the server tokenises: the system header, the message
        history (Anthropic blocks + OpenAI dicts both honoured by
        ``count_message_tokens`` after the 2026-04-30 patch) and the tool
        schemas (their JSON serialisation is what the model actually sees).
        """
        try:
            from core.memory.tokens import count_message_tokens, count_tokens
        except Exception:
            return 0
        total = count_message_tokens(messages or [])
        if system_text:
            total += count_tokens(system_text)
        if tools:
            try:
                total += count_tokens(json.dumps(tools, default=str))
            except Exception:
                # Fallback: walk and count names/descriptions.
                for t in tools:
                    if isinstance(t, dict):
                        total += count_tokens(str(t.get("name", "")))
                        total += count_tokens(str(t.get("description", "")))
        return total

    def _prompt_budget_guard(
        self,
        messages: list,
        *,
        system_text: str = "",
        tools: list | None = None,
        iteration: int = 0,
    ) -> tuple[list, bool]:
        """Pre-flight guard: enforce ``SAP_PROMPT_TOKEN_BUDGET``.

        Returns ``(maybe_pruned_messages, is_overflow_unrecoverable)``.

        Strategy when over budget:
          1. Aggressive in-place truncation of the longest tool-result
             content in ``messages`` (head+tail keeping shape), iterating
             until under budget or no more candidates.
          2. If still over budget: emit ``error`` event and return
             overflow=True so the caller can abort the iteration.

        Always emits a ``token_budget`` observability event when total
        exceeds ``SAP_PROMPT_TOKEN_WARN`` (so dashboards show the trend
        before the wall is hit).
        """
        total = self._measure_prompt(messages, system_text=system_text, tools=tools)
        if _PROMPT_TOKEN_WARN > 0 and total >= _PROMPT_TOKEN_WARN:
            try:
                self._on_message(
                    "token_budget",
                    f"iter={iteration} tokens={total}/{_PROMPT_TOKEN_BUDGET}",
                )
            except Exception:
                pass
        if total <= _PROMPT_TOKEN_BUDGET:
            return messages, False

        # Try to shrink: truncate the largest string content first.
        pruned = list(messages)
        max_passes = 8
        cap = max(2048, _CALLBACK_RESULT_CAP)
        for _pass in range(max_passes):
            longest_idx, longest_len = -1, 0
            for i, m in enumerate(pruned):
                content = m.get("content") if isinstance(m, dict) else None
                if isinstance(content, str):
                    if len(content) > longest_len:
                        longest_len, longest_idx = len(content), i
                elif isinstance(content, list):
                    # tool_results are typically lists of dicts with ``content`` text.
                    for j, blk in enumerate(content):
                        if isinstance(blk, dict):
                            txt = blk.get("content") or blk.get("text")
                            if isinstance(txt, str) and len(txt) > longest_len:
                                longest_len, longest_idx = len(txt), (i, j)
            if longest_idx == -1 or longest_len <= cap:
                break
            # Truncate the longest payload in place.
            if isinstance(longest_idx, tuple):
                i, j = longest_idx
                blk = pruned[i]["content"][j]
                key = "content" if "content" in blk else "text"
                blk[key] = self._truncate_for_callback(blk[key])
            else:
                m = pruned[longest_idx]
                # Replace with a copy to avoid mutating the original dict.
                pruned[longest_idx] = {**m, "content": self._truncate_for_callback(m["content"])}
            new_total = self._measure_prompt(pruned, system_text=system_text, tools=tools)
            try:
                self._on_message(
                    "token_budget",
                    f"iter={iteration} pruned tokens={new_total}/{_PROMPT_TOKEN_BUDGET}",
                )
            except Exception:
                pass
            if new_total <= _PROMPT_TOKEN_BUDGET:
                return pruned, False
            total = new_total
        # Could not shrink under budget — overflow.
        try:
            self._on_message(
                "error",
                f"prompt budget overflow after pruning: {total}>{_PROMPT_TOKEN_BUDGET} "
                f"at iter {iteration}; aborting to avoid HTTP 400 from llama-server.",
            )
        except Exception:
            pass
        return pruned, True

    @staticmethod
    def _tool_call_signature(name: str, args: dict) -> str:
        try:
            payload = json.dumps(args, sort_keys=True, default=str)
        except Exception:
            payload = repr(args)
        # sha1 is used here as a non-cryptographic content hash for the fuzzy
        # repetition detector (RepetitionHandler); collision attacks are
        # not in this code path's threat model.
        return hashlib.sha1(f"{name}|{payload}".encode()).hexdigest()  # noqa: S324

    # Keys whose CSV values should be tokenised individually so that
    # ``severity="critical,high"`` and ``severity="critical,high,medium"``
    # share most tokens (closes the Phase 3 loophole where the LLM
    # appended one more level to bypass the breaker).
    _CSV_TOKENISE_KEYS = frozenset({
        "severity", "tags", "templates", "ports", "levels", "extensions",
        "wordlists", "modules",
    })

    @staticmethod
    def _canonicalise_url(value: str) -> str:
        """Reduce a URL to its host part (lowercase, no ``www.``).

        Returns the original string when it does not look like an HTTP
        URL or parsing fails. Only used by the fuzzy tokeniser, so a
        best-effort match is fine — never raises.
        """
        if not isinstance(value, str):
            return value
        if not value[:8].lower().startswith(("http://", "https://")):
            return value
        try:
            from urllib.parse import urlsplit
            parts = urlsplit(value)
            host = (parts.hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
            return host or value
        except Exception:
            return value

    @classmethod
    def _tool_call_token_set(cls, name: str, args: dict) -> frozenset[str]:
        """Bag-of-tokens for fuzzy circuit-breaker matching.

        Two normalisations make the breaker robust to common LLM
        permutation tactics:

        * URL-aware: ``http://x``, ``https://x``, ``https://www.x/`` all
          collapse to the bare host so the agent can't dodge the breaker
          by toggling scheme/www/trailing-slash.
        * CSV-aware: known list-valued args (``severity`` etc.) split on
          ``,`` so adding/removing a level bumps Jaccard, not signature.
        """
        out: set[str] = {f"@{name}"}
        canon_args: dict = {}
        try:
            for key, val in (args or {}).items():
                if isinstance(val, str):
                    canon = cls._canonicalise_url(val)
                    canon_args[key] = canon
                    if key in cls._CSV_TOKENISE_KEYS and "," in canon:
                        for piece in canon.split(","):
                            piece = piece.strip()
                            if piece:
                                out.add(piece.lower())
                    else:
                        out.add(canon.lower()[:64])
                elif isinstance(val, (list, tuple)):
                    canon_args[key] = list(val)
                    for item in val:
                        if isinstance(item, str) and item:
                            out.add(item.lower()[:64])
                else:
                    canon_args[key] = val
        except Exception:
            canon_args = args if isinstance(args, dict) else {}

        # Fallback tokenisation over the *canonicalised* JSON payload —
        # keeps prior behaviour for nested / unusual arg shapes without
        # reintroducing raw URLs that were just normalised away.
        try:
            payload = json.dumps(canon_args, sort_keys=True, default=str)
        except Exception:
            payload = repr(canon_args)
        import re as _re
        for tok in _re.findall(r"[A-Za-z0-9_.:/\\-]+", payload):
            if tok and len(tok) <= 64:
                out.add(tok.lower())
        return frozenset(out)

    def _fuzzy_signature(self, name: str, args: dict, threshold: float = 0.85) -> str:
        """Resolve ``(name, args)`` to a canonical signature.

        Returns the SHA1 signature of the *closest* prior call whose
        Jaccard similarity is ≥ ``threshold``. If no prior call is
        similar enough, returns the exact SHA1 signature and registers
        it in the lookup table for future calls.
        """
        if not hasattr(self, "_fuzzy_index"):
            # ``list[(token_set, signature)]``; capped at 256 entries.
            self._fuzzy_index: list[tuple[frozenset[str], str]] = []  # type: ignore[attr-defined]
        new_tokens = self._tool_call_token_set(name, args)
        sig = self._tool_call_signature(name, args)
        # Search recent prior calls for a near-duplicate.
        best: tuple[float, str] | None = None
        for tokens, prior_sig in self._fuzzy_index[-256:]:
            if not tokens or not new_tokens:
                continue
            inter = len(tokens & new_tokens)
            if not inter:
                continue
            union = len(tokens | new_tokens)
            jaccard = inter / union if union else 0.0
            if jaccard >= threshold and (best is None or jaccard > best[0]):
                best = (jaccard, prior_sig)
        chosen = best[1] if best is not None else sig
        self._fuzzy_index.append((new_tokens, chosen))
        # Cap memory.
        if len(self._fuzzy_index) > 512:
            self._fuzzy_index = self._fuzzy_index[-256:]
        return chosen


    async def _emit_repetition_decision(self, tool_name: str, args: dict, summary: str) -> None:
        """Surface a structured decision event when the circuit-breaker fires.

        Best-effort: never raises. Emits both on the message bus (so the
        dashboard can react) and into the audit log when one is wired.
        """
        try:
            self._on_message("decision", f"repetition_blocked: {tool_name} :: {summary}")
        except Exception:
            pass
        if self._audit_log is None or not self._engagement_id:
            return
        try:
            from core.adaptive.decisions import DecisionKind, emit_decision
            await emit_decision(
                self._audit_log,
                engagement_id=self._engagement_id,
                kind=DecisionKind.REPETITION_BLOCKED,
                summary=summary,
                target=tool_name,
                details={
                    "tool": tool_name,
                    "args_signature": self._tool_call_signature(tool_name, args),
                    "limit": _TOOL_LOOP_LIMIT,
                    "run_id": self._run_id,
                },
            )
        except Exception:
            pass

    # ── Phase 4: anti-monotony runtime ────────────────────────────────────

    @staticmethod
    def _extract_target(args: dict) -> str:
        """Best-effort target identifier for the tactics_log line."""
        if not isinstance(args, dict):
            return "-"
        for key in ("target", "host", "url", "ip", "address", "engagement_id"):
            v = args.get(key)
            if isinstance(v, str) and v:
                return v
        return "-"

    async def _record_tactic(
        self, tool_name: str, args: dict, result_str: str, *, status: str | None = None
    ) -> None:
        """Append a one-line entry to the tactics_log core memory block.

        Best-effort; never raises. Skips silently when memory or the
        adaptive layer are disabled (legacy behaviour preserved).
        """
        if not _MEMORY_ENABLED or self._memory is None:
            return
        settings = self._adaptive_settings
        if settings is None or not settings.is_active:
            return
        try:
            from core.adaptive.repetition import (
                derive_tactic_status,
                format_tactic_entry,
            )
            label = status or derive_tactic_status(result_str)
            outcome = self._summarize_result_for_tactic(result_str)
            line = format_tactic_entry(
                status=label,
                tool=tool_name,
                target=self._extract_target(args),
                outcome=outcome,
            )
            await self._memory.append_block("tactics_log", line)
        except Exception as exc:
            try:
                self._on_message("error", f"tactics_log append failed: {exc}")
            except Exception:
                pass

    @staticmethod
    def _summarize_result_for_tactic(result_str: str) -> str:
        if not result_str:
            return "no output"
        snippet = result_str.strip().replace("\n", " ")
        # Head+tail split keeps both the opening context (often the command/
        # parser banner) and the trailing summary (returncode, count, vuln).
        if len(snippet) <= 200:
            return snippet
        return snippet[:100] + " … " + snippet[-100:]

    async def _maybe_pivot(
        self, tool_name: str, args: dict, last_result: str
    ) -> dict | None:
        """Pick a pivot suggestion when auto-pivot is allowed.

        Returns a dict with keys ``suggested_tool`` / ``fallback_kind`` /
        ``rationale`` / ``failure_class`` if a pivot was emitted, ``None``
        otherwise (legacy plain-abort behaviour).
        """
        settings = self._adaptive_settings
        if settings is None or not settings.is_active or not settings.auto_pivot:
            return None
        handler = self._repetition_handler
        if handler is None or handler.is_exhausted():
            return None
        try:
            from core.adaptive.decisions import DecisionKind, emit_decision
            suggestion = handler.suggest(
                tool_name=tool_name,
                last_result=last_result,
                playbook=self._adaptive_playbook,
            )
        except Exception as exc:
            try:
                self._on_message("error", f"auto-pivot failed: {exc}")
            except Exception:
                pass
            return None

        payload = suggestion.to_dict()
        try:
            self._on_message(
                "decision",
                f"repetition_pivot: {tool_name} -> {suggestion.suggested_tool or suggestion.fallback_kind} "
                f"({suggestion.failure_class})",
            )
        except Exception:
            pass
        try:
            await emit_decision(
                self._audit_log,
                engagement_id=self._engagement_id,
                kind=DecisionKind.REPETITION_PIVOT,
                summary=(
                    f"pivot from '{tool_name}' to "
                    f"{suggestion.suggested_tool or suggestion.fallback_kind}"
                ),
                target=tool_name,
                details={
                    "tool": tool_name,
                    "args_signature": self._tool_call_signature(tool_name, args),
                    "pivots_remaining": handler.remaining_pivots,
                    "run_id": self._run_id,
                    **payload,
                },
            )
        except Exception:
            pass
        # Track in tactics_log so the agent can avoid the same dead-end.
        try:
            from core.adaptive.repetition import format_tactic_entry
            line = format_tactic_entry(
                status="pivot",
                tool=tool_name,
                target=self._extract_target(args),
                outcome=(
                    f"-> {suggestion.suggested_tool or suggestion.fallback_kind} "
                    f"({suggestion.failure_class})"
                ),
            )
            if _MEMORY_ENABLED and self._memory is not None:
                await self._memory.append_block("tactics_log", line)
        except Exception:
            pass
        return payload

    async def initialize(self) -> None:
        await self._registry.build()
        if _MEMORY_ENABLED:
            self._registry.register_builtin(builtin_tool_specs())

    @property
    def gate(self) -> ApprovalGate:
        return self._gate

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def plan(self) -> Plan | None:
        return self._plan

    # ── Tool dispatch with mode awareness ──────────────────────────────────────────────────

    async def _dispatch_tool(self, name: str, args: dict, tool_call_id: str) -> str:
        """Route a tool call through the mode-specific gate / planner."""
        # Builtin memory tools never need human approval and never count
        # against planning mode (they shape the agent's own context).
        if _MEMORY_ENABLED and self._memory is not None and self._registry.is_builtin(name):
            return await dispatch_builtin_tool(name, args, self._memory)

        # STEP MODE: every call needs human approval
        if self._mode is RunMode.STEP:
            decision = await self._gate.request(
                reason="step_mode",
                summary=f"{name}({json.dumps(args, default=str)[:300]})",
                details={"tool": name, "args": args, "tool_call_id": tool_call_id},
            )
            if decision.action != "allow":
                return json.dumps({
                    "skipped": True, "reason": decision.reason or "denied by operator",
                })

        # PLANNING MODE: never execute, just record
        if self._mode is RunMode.PLANNING:
            if self._plan is not None:
                self._plan.append_step(
                    tool=name, args=args, rationale=self._last_thinking[:1000],
                )
            return json.dumps({
                "plan_only": True, "would_execute": name, "args": args,
                "note": "no real tool call performed",
            })

        # EXECUTION MODE
        result = await self._registry.call(name, args)
        # ── Reporting autopilot (C3) ────────────────────────────────────
        # Ensure a report exists on disk after a phase transition into
        # "reporting" or right before / after engagement completion.
        try:
            await self._maybe_autoreport(name, args)
        except Exception as exc:  # pragma: no cover - autopilot must never break dispatch
            self._on_message("error", f"autoreport failed: {exc}")
        return result

    async def _maybe_autoreport(self, name: str, args: dict) -> None:
        """Trigger ``generate_assessment_report`` on phase/complete events.

        Idempotent within a turn via ``self._autoreport_done_for``: each
        engagement gets at most one auto-invocation per orchestrator run
        (manual user calls remain free to fire additional reports).
        """
        if not isinstance(args, dict):
            return
        eng_id = args.get("engagement_id") or self._engagement_id
        if not eng_id:
            return
        trigger = False
        if name == "set_phase" and str(args.get("phase", "")).lower() == "reporting":
            trigger = True
        elif name == "complete_engagement":
            trigger = True
        if not trigger:
            return
        if not hasattr(self, "_autoreport_done_for"):
            self._autoreport_done_for = set()  # type: ignore[attr-defined]
        if eng_id in self._autoreport_done_for:
            return
        self._autoreport_done_for.add(eng_id)
        # Skip if a report already exists on disk for this engagement
        try:
            reports_dir = Path(os.environ.get("REPORTS_DIR", "./reports"))
            if reports_dir.exists():
                existing = list(reports_dir.glob(f"{eng_id}_*.md"))
                if existing and name == "set_phase":
                    # Phase transition is enough — don't re-generate if a
                    # report already exists. complete_engagement always
                    # forces a fresh report.
                    self._on_message(
                        "autoreport",
                        f"skipped: report already on disk ({existing[-1].name})",
                    )
                    return
        except Exception:
            pass
        self._on_message("autoreport", f"invoking generate_assessment_report({eng_id})")
        try:
            res = await self._registry.call(
                "generate_assessment_report",
                {"engagement_id": eng_id, "format_type": "markdown"},
            )
            self._on_message("autoreport_result", self._truncate_for_callback(res))
        except Exception as exc:
            self._on_message("error", f"autoreport invocation failed: {exc}")

    async def run(
        self,
        engagement_id: str,
        objective: str,
        max_iterations: int = MAX_ITERATIONS,
    ) -> str:
        """
        Run the agent on a specific objective for an engagement.
        Returns the final agent response as a string.
        """
        self._engagement_id = engagement_id

        # Initialize plan if planning mode
        if self._mode is RunMode.PLANNING:
            self._plan = Plan(
                engagement_id=engagement_id, objective=objective, model=_MODEL,
                mode=self._mode,
            )

        # Bring up the long-term memory layer for this run.
        if _MEMORY_ENABLED:
            self._memory = MemoryManager(
                engagement_id=engagement_id, run_id=self._run_id,
            )
            self._memory.set_summary_fn(self._llm_summarize)
            await self._memory.initialize(engagement_record=await self._load_engagement_record(engagement_id))

        # Adaptive layer (Phase 3): classify the engagement scenario and pick
        # a tactical playbook. Behaviour is gated by `adaptive.rollout_mode`
        # in config.yaml — `shadow` only emits a decision audit, `advisory`
        # additionally writes the playbook hint into the scratchpad block.
        await self._run_adaptive_classification(engagement_id)

        # Bind every MCP server's ToolExecutor to this run_id so that
        # ToolOutputStore.put() actually persists stdout/stderr to disk.
        # Without this, the executors are constructed with run_id="" and
        # spill-to-disk is silently OFF — meaning ``read_tool_output_*``
        # later returns ``call_id not found``. Fire-and-forget per server.
        await self._broadcast_run_context()

        # Prepend engagement context to the user message
        user_message = (
            f"Engagement ID: {engagement_id}\n\n"
            f"Objective: {objective}\n\n"
            f"Run mode: {self._mode.value}\n\n"
            f"Begin by loading the engagement details with get_engagement, "
            f"then follow the PTES methodology."
        )

        if _PROVIDER == "anthropic":
            final = await self._run_anthropic(user_message, max_iterations)
        elif _PROVIDER in ("openai", "local"):
            final = await self._run_openai(user_message, max_iterations)
        else:
            raise RuntimeError(f"Unsupported provider: {_PROVIDER}")

        # Persist plan
        if self._plan is not None:
            try:
                plans_dir = (
                    _REPO_ROOT / "sessions" / "engagements" / engagement_id / "plans"
                )
                plans_dir.mkdir(parents=True, exist_ok=True)
                out = plans_dir / f"{self._plan.plan_id}.json"
                out.write_text(self._plan.model_dump_json(indent=2), encoding="utf-8")
                self._on_message("plan_saved", str(out))
            except Exception as e:
                self._on_message("error", f"failed to save plan: {e}")

        return final

    # ── Anthropic loop ─────────────────────────────────────────────────────────

    async def _run_anthropic(self, user_message: str, max_iter: int) -> str:
        base_system = "\n\n".join(
            s for s in (SYSTEM_PROMPT, _mode_prompt(self._mode)) if s
        )
        tools = self._registry.anthropic_tools()
        final_text = ""
        messages = [{"role": "user", "content": user_message}]
        if _MEMORY_ENABLED and self._memory is not None:
            await self._memory.record("user", user_message)

        for iteration in range(max_iter):
            self._on_message("iteration", str(iteration + 1))
            # Refresh system header (core blocks may have changed) + compact if needed.
            system_text = await self._compose_system(base_system)
            # _maybe_compact expects an OpenAI-style list with the system header
            # at index 0. Wrap accordingly, run compaction, then unwrap.
            wrapped = [{"role": "system", "content": system_text}, *messages]
            wrapped = await self._maybe_compact(wrapped)
            system_text = wrapped[0]["content"]
            messages = wrapped[1:]

            # Pre-flight prompt-budget guard (defence-in-depth: even after
            # compaction the next call may still overshoot n_ctx, e.g.
            # because of a fresh huge tool_result appended this turn).
            messages, _overflow = self._prompt_budget_guard(
                messages,
                system_text=system_text,
                tools=tools,
                iteration=iteration,
            )
            if _overflow:
                return final_text

            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        _llm.messages.create,
                        model=_MODEL,
                        max_tokens=8096,
                        system=system_text,
                        tools=tools,
                        messages=messages,
                    ),
                    timeout=_LLM_REQUEST_TIMEOUT,
                )
            except TimeoutError:
                self._on_message(
                    "error",
                    f"LLM call timed out after {_LLM_REQUEST_TIMEOUT}s "
                    f"at iteration {iteration}; aborting run.",
                )
                return final_text
            except Exception as exc:
                self._on_message(
                    "error",
                    f"LLM call failed at iteration {iteration}: "
                    f"{type(exc).__name__}: {exc}",
                )
                return final_text

            # Collect text and tool_use blocks
            tool_calls = []
            text_parts = []

            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_calls.append(block)

            if text_parts:
                text = "\n".join(text_parts)
                final_text = text
                self._last_thinking = text
                self._on_message("assistant", text)
                if _MEMORY_ENABLED and self._memory is not None:
                    await self._memory.record("assistant", text)

            # If no tool calls, we're done
            if response.stop_reason == "end_turn" or not tool_calls:
                break

            # Execute all tool calls
            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for tc in tool_calls:
                self._on_message("tool_call", f"{tc.name}({json.dumps(tc.input)})")
                # Phase 5: fuzzy-match collapses near-duplicate calls onto
                # a single counter so the LLM cannot bypass the breaker by
                # appending a no-op flag.
                sig = self._fuzzy_signature(tc.name, tc.input)
                self._tool_call_counts[sig] += 1
                if self._tool_call_counts[sig] > _TOOL_LOOP_LIMIT:
                    msg = (
                        f"circuit-breaker: tool '{tc.name}' invoked with identical "
                        f"arguments more than {_TOOL_LOOP_LIMIT} times; aborting loop."
                    )
                    self._on_message("error", msg)
                    await self._emit_repetition_decision(tc.name, tc.input, msg)
                    pivot = await self._maybe_pivot(tc.name, tc.input, last_result="")
                    abort_payload = {"aborted": True, "reason": msg}
                    if pivot is not None:
                        abort_payload["pivot"] = pivot
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": json.dumps(abort_payload),
                    })
                    messages.append({"role": "user", "content": tool_results})
                    return final_text
                result_str = await self._dispatch_tool(tc.name, tc.input, tc.id)
                self._on_message("tool_result", self._truncate_for_callback(result_str))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.id,
                    "content": result_str,
                })
                if _MEMORY_ENABLED and self._memory is not None:
                    await self._memory.record(
                        "tool", result_str,
                        tool_call_id=tc.id, tool_name=tc.name,
                    )
                await self._record_tactic(tc.name, tc.input, result_str)

            messages.append({"role": "user", "content": tool_results})
            await asyncio.sleep(0)

        return final_text

    # ── OpenAI / local loop ────────────────────────────────────────────────────

    async def _compose_system(self, base_system: str) -> str:
        """Combine static system prompt with live core memory + summary."""
        if not _MEMORY_ENABLED or self._memory is None:
            return base_system
        blocks = await self._memory.get_blocks()
        from core.memory.blocks import render_blocks
        block_text = render_blocks(blocks)
        parts = [base_system, block_text]
        if self._memory._summary_text:  # noqa: SLF001 - intentional facade access
            parts.append(
                "<recap_of_earlier_conversation>\n"
                + self._memory._summary_text  # noqa: SLF001
                + "\n</recap_of_earlier_conversation>"
            )
        return "\n\n".join(p for p in parts if p).strip()

    async def _maybe_compact(self, messages: list[dict]) -> list[dict]:
        """If projected token cost exceeds budget, summarize the oldest slice
        of *messages* (excluding the system header) and replace it with a
        single system note. Returns the (possibly mutated) message list."""
        if not _MEMORY_ENABLED or self._memory is None:
            return messages
        from core.memory.summarizer import summarize as _summarize
        from core.memory.tokens import count_message_tokens
        if count_message_tokens(messages) < self._memory._trigger:  # noqa: SLF001
            return messages
        # Always preserve the system header (idx 0) and the last keep_recent
        keep = self._memory._keep_recent  # noqa: SLF001
        if len(messages) <= keep + 1:
            return messages
        body = messages[1:]
        old, recent = body[:-keep], body[-keep:]
        if not old:
            return messages
        text = await _summarize(
            [{"role": m.get("role", "?"), "content": str(m.get("content", "") or "")} for m in old],
            self._llm_summarize,
        )
        prev = self._memory._summary_text  # noqa: SLF001
        self._memory._summary_text = (prev + "\n\n" + text).strip() if prev else text  # noqa: SLF001
        if len(self._memory._summary_text) > 6000:  # noqa: SLF001
            self._memory._summary_text = self._memory._summary_text[-6000:]  # noqa: SLF001
        # Rebuild system header with the new summary baked in.
        new_system = await self._compose_system(messages[0]["content"].split("\n\n<core_memory>")[0])
        self._on_message(
            "memory_compact",
            f"compacted {len(old)} messages into {len(text)}-char summary",
        )
        return [{"role": "system", "content": new_system}, *recent]

    async def _llm_summarize(self, prompt: str) -> str:
        """Summarizer hook used by MemoryManager — calls the same LLM."""
        try:
            if _PROVIDER == "anthropic":
                resp = await asyncio.wait_for(
                    asyncio.to_thread(
                        _llm.messages.create,
                        model=_MODEL,
                        max_tokens=600,
                        system="You are a precise memory compactor. Output dense bullets.",
                        messages=[{"role": "user", "content": prompt}],
                    ),
                    timeout=_LLM_REQUEST_TIMEOUT,
                )
                return "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
            resp = await asyncio.wait_for(
                asyncio.to_thread(
                    _llm_oai.chat.completions.create,
                    model=_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a precise memory compactor. Output dense bullets only, no preamble."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=600,
                    temperature=0.2,
                ),
                timeout=_LLM_REQUEST_TIMEOUT,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            self._on_message("error", f"summarizer failed: {exc}")
            return ""

    async def _load_engagement_record(self, engagement_id: str) -> dict | None:
        """Best-effort lookup so the 'engagement' core block has scope info."""
        try:
            from core.session_store import SessionStore
            store = SessionStore()
            await store.init()
            eng = await store.get_engagement(engagement_id)
            if eng is None:
                return None
            return {
                "id": eng.id, "name": eng.name, "client": eng.client,
                "current_phase": eng.current_phase.value if hasattr(eng.current_phase, "value") else str(eng.current_phase),
                "scope_cidrs": eng.scope_cidrs, "scope_domains": eng.scope_domains,
                "scope_urls": eng.scope_urls,
            }
        except Exception:
            return None

    async def _broadcast_run_context(self) -> None:
        """Bind every MCP server's ToolExecutor to ``self._run_id``.

        The MCP servers expose a ``set_run_context_<suffix>`` meta-tool (see
        ``mcp_servers/_response.register_run_context_tool``). We fan-out a
        call to every variant present in the registry; missing tools are
        silently skipped so that a partial deployment keeps working.

        Best-effort: failures emit a ``warning`` event but never abort the
        run. Persistence will simply remain disabled on the affected server.
        """
        suffixes = ("recon", "exploit", "parrot", "osint")
        for suffix in suffixes:
            tool_name = f"set_run_context_{suffix}"
            if tool_name not in self._registry._tool_to_server:
                continue
            try:
                resp = await self._registry.call(
                    tool_name,
                    {"run_id": self._run_id, "engagement_id": self._engagement_id},
                )
                self._on_message("run_context", f"{suffix}: {resp}")
            except Exception as exc:
                self._on_message(
                    "warning",
                    f"set_run_context_{suffix} failed: {type(exc).__name__}: {exc}",
                )

    async def _run_adaptive_classification(self, engagement_id: str) -> None:
        """Phase 3 entry point — classify scenario + pick playbook.

        Best-effort: any failure here is logged on the message bus and the
        run continues unmodified. This keeps the legacy execution path
        immune to bugs in the adaptive layer.
        """
        try:
            from core.adaptive import (
                DecisionKind,
                PlaybookRouter,
                RolloutMode,
                ScenarioClassifier,
                emit_decision,
                load_adaptive_settings,
                render_advisory,
            )
        except Exception as exc:
            self._on_message("error", f"adaptive import failed: {exc}")
            return

        settings = load_adaptive_settings()
        if not settings.is_active:
            return
        # Stash for phase-4 helpers (auto-pivot, tactics_log).
        self._adaptive_settings = settings
        try:
            from core.adaptive.repetition import RepetitionHandler
            self._repetition_handler = RepetitionHandler(
                max_pivots=int(settings.max_pivots_per_run)
            )
        except Exception:
            self._repetition_handler = None

        # Gather the snapshot the classifier needs.
        record = await self._load_engagement_record(engagement_id) or {}
        scope = {
            "scope_cidrs": record.get("scope_cidrs") or [],
            "scope_domains": record.get("scope_domains") or [],
            "scope_urls": record.get("scope_urls") or [],
        }
        hosts: list[dict] = []
        findings: list[dict] = []
        try:
            from core.session_store import SessionStore
            store = SessionStore()
            await store.init()
            for h in await store.get_hosts(engagement_id):
                hosts.append(h.model_dump(mode="json"))
            for f in await store.get_findings(engagement_id):
                findings.append(f.model_dump(mode="json"))
        except Exception:
            pass  # Empty engagement is fine — classifier will tag as "mixed".

        scenario = ScenarioClassifier.classify(
            scope=scope, hosts=hosts, findings=findings,
        )
        if not settings.scenario_allowed(scenario.type):
            self._on_message(
                "decision",
                f"scenario '{scenario.type}' disabled by config; skipping playbook injection",
            )
            return

        playbook = PlaybookRouter.load_or_none(scenario.type)
        current_phase = record.get("current_phase") or "reconnaissance"
        advisory_text = ""
        if playbook is not None:
            advisory_text = render_advisory(playbook, current_phase)
        self._adaptive_playbook = playbook
        self._adaptive_scenario = scenario

        # Always emit the decision (KPI baseline). emit_decision is no-op
        # when audit_log is None, so this is safe in tests.
        if settings.emit_decision_audit:
            await emit_decision(
                self._audit_log,
                engagement_id=engagement_id,
                kind=DecisionKind.SCENARIO_CLASSIFIED,
                summary=f"scenario={scenario.type} confidence={scenario.confidence:.2f}",
                details={
                    "scenario": scenario.to_dict(),
                    "current_phase": current_phase,
                    "playbook_loaded": playbook is not None,
                    "rollout_mode": settings.rollout_mode.value,
                    "run_id": self._run_id,
                },
                target=engagement_id,
            )

        self._on_message(
            "decision",
            f"scenario_classified: {scenario.type} ({scenario.confidence:.2f}) :: "
            f"indicators={list(scenario.indicators)}",
        )

        # Advisory / enforce: surface the tactical hint to the agent through
        # the scratchpad core memory block. Shadow mode stops at the audit.
        if (
            settings.rollout_mode in (RolloutMode.ADVISORY, RolloutMode.ENFORCE)
            and advisory_text
            and _MEMORY_ENABLED
            and self._memory is not None
        ):
            try:
                await self._memory.append_block(
                    "scratchpad",
                    "\n\n" + advisory_text + "\n",
                )
            except Exception as exc:
                self._on_message("error", f"adaptive scratchpad append failed: {exc}")

    async def _run_openai(self, user_message: str, max_iter: int) -> str:
        # Inject /no_think or /think control token for Qwen3.
        # /no_think suppresses chain-of-thought during tool-call iterations
        # to save context tokens.  Set LOCAL_THINK_MODE=think for full CoT.
        think_directive = f"/{_THINK_MODE}\n" if _PROVIDER == "local" else ""
        mode_addendum = _mode_prompt(self._mode)
        base_system = "\n\n".join(
            s for s in (think_directive + SYSTEM_PROMPT, mode_addendum) if s
        ).strip()

        system_content = await self._compose_system(base_system)
        messages = [
            {"role": "system", "content": system_content},
            {"role": "user",   "content": user_message},
        ]
        if _MEMORY_ENABLED and self._memory is not None:
            await self._memory.record("user", user_message)
        tools = self._registry.openai_tools()
        final_text = ""

        for _iteration in range(max_iter):
            self._on_message("iteration", str(_iteration + 1))
            # Refresh system header (core blocks may have changed) + compact if needed
            messages[0] = {"role": "system", "content": await self._compose_system(base_system)}
            messages = await self._maybe_compact(messages)

            # Pre-flight prompt-budget guard (see _prompt_budget_guard).
            # The OpenAI loop carries the system header inside ``messages``,
            # so we pass system_text="" to avoid double-counting.
            messages, _overflow = self._prompt_budget_guard(
                messages,
                tools=tools if tools else None,
                iteration=_iteration,
            )
            if _overflow:
                return final_text

            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        _llm_oai.chat.completions.create,
                        model=_MODEL,
                        messages=messages,
                        tools=tools if tools else _openai_lib.NOT_GIVEN,
                        tool_choice="auto" if tools else _openai_lib.NOT_GIVEN,
                        max_tokens=_MAX_TOKENS,
                        # llama.cpp prefix cache: reuses KV for the static
                        # prompt prefix across turns of the agentic loop.
                        # Ignored by upstream OpenAI (passes through as
                        # extra_body). Drops TTFT 30-70 % on multi-step runs.
                        extra_body={"cache_prompt": True},
                    ),
                    timeout=_LLM_REQUEST_TIMEOUT,
                )
            except TimeoutError:
                self._on_message(
                    "error",
                    f"LLM call timed out after {_LLM_REQUEST_TIMEOUT}s "
                    f"at iteration {_iteration}; aborting run. "
                    "Consider lowering context (SAP_MEM_TRIGGER_TOKENS) "
                    "or raising SAP_LLM_REQUEST_TIMEOUT.",
                )
                return final_text
            except Exception as exc:
                self._on_message(
                    "error",
                    f"LLM call failed at iteration {_iteration}: "
                    f"{type(exc).__name__}: {exc}",
                )
                return final_text

            msg = response.choices[0].message
            raw_content = msg.content or ""
            # llama.cpp/jinja splits Qwen3 thinking into `reasoning_content`;
            # legacy servers inline <think>…</think> in `content`. Handle both.
            reasoning = getattr(msg, "reasoning_content", None) or ""

            # Strip Qwen3 <think>…</think> CoT tokens from visible output.
            visible, inline_think = _strip_thinking(raw_content)
            thinking = (reasoning + "\n" + inline_think).strip()
            if thinking:
                self._on_message("thinking", thinking)
                self._last_thinking = thinking
            if visible:
                final_text = visible
                self._last_thinking = visible
                self._on_message("assistant", visible)
                if _MEMORY_ENABLED and self._memory is not None:
                    await self._memory.record("assistant", visible)

            # No tool calls → done
            if not msg.tool_calls:
                break

            # Keep original content (with CoT) in context if think mode is on
            messages.append({
                "role": "assistant",
                "content": raw_content or None,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                self._on_message("tool_call", f"{tc.function.name}({tc.function.arguments})")
                # Phase 5: fuzzy circuit-breaker (Jaccard ≥ 0.85).
                sig = self._fuzzy_signature(tc.function.name, args)
                self._tool_call_counts[sig] += 1
                if self._tool_call_counts[sig] > _TOOL_LOOP_LIMIT:
                    abort_msg = (
                        f"circuit-breaker: tool '{tc.function.name}' invoked with "
                        f"identical arguments more than {_TOOL_LOOP_LIMIT} times; "
                        "aborting loop."
                    )
                    self._on_message("error", abort_msg)
                    await self._emit_repetition_decision(tc.function.name, args, abort_msg)
                    pivot = await self._maybe_pivot(tc.function.name, args, last_result="")
                    abort_payload = {"aborted": True, "reason": abort_msg}
                    if pivot is not None:
                        abort_payload["pivot"] = pivot
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(abort_payload),
                    })
                    return final_text
                result_str = await self._dispatch_tool(tc.function.name, args, tc.id)
                # Truncate for the dashboard / WebSocket callback only; the
                # full result is still appended to the LLM context below.
                self._on_message("tool_result", self._truncate_for_callback(result_str))
                # P1.10 hardening: sanitize before feeding back to the model.
                # Strips control chars, redacts secrets, caps size, and wraps
                # the payload in an explicit fence so the LLM treats it as
                # untrusted data rather than instructions.
                sanitized = sanitize_tool_output(
                    result_str,
                    tool_name=tc.function.name,
                    call_id=tc.id,
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": sanitized,
                })
                if _MEMORY_ENABLED and self._memory is not None:
                    await self._memory.record(
                        "tool", result_str,
                        tool_call_id=tc.id, tool_name=tc.function.name,
                    )
                await self._record_tactic(tc.function.name, args, result_str)
            await asyncio.sleep(0)

        return final_text

    async def close(self) -> None:
        await self._registry.close()


# ── Convenience entry point ───────────────────────────────────────────────────

async def run_agent(
    engagement_id: str,
    objective: str,
    on_message=None,
    mode: RunMode = RunMode.EXECUTION,
    approval_gate: ApprovalGate | None = None,
    run_id: str | None = None,
) -> str:
    agent = Orchestrator(
        on_message=on_message, mode=mode,
        approval_gate=approval_gate, run_id=run_id,
    )
    await agent.initialize()
    try:
        return await agent.run(engagement_id=engagement_id, objective=objective)
    finally:
        await agent.close()
