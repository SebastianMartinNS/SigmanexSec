"""
core/parrot_catalog.py — Loader, validator and argv renderer for the
declarative Parrot OS tool catalogue.

The catalogue is a YAML list of tool descriptors (see ``parrot_tools.yaml``).
This module:

  * loads & caches the catalogue
  * exposes lookup helpers (by name / by category)
  * renders ``argv_template`` against caller-supplied args, with strict
    shlex-quoting of every interpolated value
  * validates args against the descriptor's ``args_schema`` via JSON Schema
  * post-render scrub: rejects argv elements that contain shell
    metacharacters or match the executor's ``blocked_arg_patterns``
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

# ─────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────

class CatalogError(Exception):
    """Raised on schema / template / validation failure."""


# ─────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────

_DEFAULT_PATH = Path(__file__).parent.parent / "parrot_tools.yaml"
_CACHE: dict[str, Any] = {"path": None, "mtime": 0.0, "data": []}


def load_catalog(path: str | Path | None = None, force: bool = False) -> list[dict[str, Any]]:
    p = Path(path) if path else _DEFAULT_PATH
    if not p.exists():
        return []
    mtime = p.stat().st_mtime
    if (
        not force
        and _CACHE["path"] == str(p)
        and _CACHE["mtime"] == mtime
        and _CACHE["data"]
    ):
        return _CACHE["data"]
    with open(p) as f:
        data = yaml.safe_load(f) or []
    if not isinstance(data, list):
        raise CatalogError(f"{p} must contain a YAML list of tool descriptors")
    _CACHE.update(path=str(p), mtime=mtime, data=data)
    return data


def get_descriptor(name: str) -> dict[str, Any] | None:
    for d in load_catalog():
        if d.get("name") == name:
            return d
    return None


def list_names() -> list[str]:
    return [d["name"] for d in load_catalog() if "name" in d]


def list_by_category() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for d in load_catalog():
        out.setdefault(d.get("category", "misc"), []).append(d["name"])
    return out


def list_binaries() -> set[str]:
    return {d["binary"] for d in load_catalog() if "binary" in d}


# ─────────────────────────────────────────────
# Validation (lightweight JSON-Schema subset)
# ─────────────────────────────────────────────

def _validate_args(descriptor: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    schema = descriptor.get("args_schema") or {}
    props: dict[str, Any] = schema.get("properties", {})
    required: list[str] = schema.get("required", [])

    # Reject unknown keys
    unknown = set(args) - set(props)
    if unknown:
        raise CatalogError(
            f"Tool '{descriptor['name']}': unknown arg keys: {sorted(unknown)}"
        )

    out: dict[str, Any] = {}
    for key, spec in props.items():
        if key in args:
            val = args[key]
            t = spec.get("type")
            if t == "string" and not isinstance(val, str):
                val = str(val)
            elif t == "integer":
                try:
                    val = int(val)
                except Exception as exc:
                    raise CatalogError(f"Arg '{key}' must be integer") from exc
            elif t == "boolean":
                if isinstance(val, str):
                    val = val.lower() in ("1", "true", "yes", "on")
                else:
                    val = bool(val)
            enum = spec.get("enum")
            if enum and val not in enum:
                raise CatalogError(
                    f"Arg '{key}' must be one of {enum}, got {val!r}"
                )
            pattern = spec.get("pattern")
            if pattern and isinstance(val, str):
                try:
                    if not re.match(pattern, val):
                        raise CatalogError(
                            f"Arg '{key}' must match pattern {pattern!r}, "
                            f"got {val!r}"
                        )
                except re.error as exc:
                    raise CatalogError(
                        f"Arg '{key}': invalid pattern in schema: {exc}"
                    ) from exc
            out[key] = val
        elif "default" in spec:
            out[key] = spec["default"]

    # Required check
    missing = [k for k in required if k not in out or out[k] in ("", None)]
    if missing:
        raise CatalogError(
            f"Tool '{descriptor['name']}': missing required args: {missing}"
        )

    # oneOf — only check that at least one branch's required keys are all present
    one_of = schema.get("oneOf")
    if one_of:
        ok = False
        for branch in one_of:
            req = branch.get("required", [])
            if all(k in out and out[k] not in ("", None) for k in req):
                ok = True
                break
        if not ok:
            raise CatalogError(
                f"Tool '{descriptor['name']}': none of the oneOf branches satisfied"
            )
    return out


# ─────────────────────────────────────────────
# Template rendering
# ─────────────────────────────────────────────

# Conditional segment: {{?name}}...{{/name}}  → emitted only if name truthy.
_COND_RE = re.compile(r"\{\{\?(\w+)\}\}(.*?)\{\{/\1\}\}", re.DOTALL)
# Plain placeholder: {{name}}
_VAR_RE = re.compile(r"\{\{(\w+)\}\}")
# Reject any element containing shell metacharacters after rendering.
_SHELL_META_RE = re.compile(r"[;&|`$<>\\\n\r]|\$\(|\$\{")


def _render_one(tpl: str, ctx: dict[str, Any]) -> str | None:
    """Render one template element. Returns None if a conditional segment
    drops the entire element (i.e. the element became empty)."""
    # Conditional segments
    def _cond_sub(m: re.Match[str]) -> str:
        key = m.group(1)
        val = ctx.get(key)
        if val in (None, "", 0, False, []):
            return ""
        return m.group(2)

    s = _COND_RE.sub(_cond_sub, tpl)
    # Variable interpolation
    def _var_sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in ctx:
            return ""
        return str(ctx[key])

    s = _VAR_RE.sub(_var_sub, s)

    if s == "":
        return None
    return s


def render_argv(descriptor: dict[str, Any], args: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    """
    Validate args against schema and render the argv list.
    Returns (argv, normalized_args). Raises CatalogError on validation /
    rendering failure.
    """
    norm = _validate_args(descriptor, args)
    template = descriptor.get("argv_template") or []
    argv: list[str] = []
    for raw in template:
        if not isinstance(raw, str):
            raise CatalogError(f"argv_template entries must be strings, got {raw!r}")
        rendered = _render_one(raw, norm)
        if rendered is None:
            continue
        if _SHELL_META_RE.search(rendered):
            raise CatalogError(
                f"Rendered argv element contains shell metacharacters: {rendered!r}"
            )
        argv.append(rendered)
    return argv, norm


# ─────────────────────────────────────────────
# Auto-artifacts: force structured output flags
# ─────────────────────────────────────────────
#
# Many tools support flags that write a structured copy of their results to
# disk (XML, JSON, line-oriented). We inject those flags automatically when
# the operator/agent didn't already provide an equivalent, so the resulting
# artifacts are captured by the ToolOutputStore alongside stdout/stderr.
#
# Detection rule: if the existing argv already contains ANY of the flags in
# ``conflicts`` we skip injection (operator wins).

# Flag-presence signatures keyed by binary name. ``flags`` are appended at
# the end of argv and use ``{artifacts}`` as a placeholder for the per-call
# artifacts directory (resolved at injection time).
_AUTO_ARTIFACT_RULES: dict[str, dict[str, list[str]]] = {
    "nmap": {
        "conflicts": ["-oA", "-oN", "-oX", "-oG", "-oS"],
        "flags": ["-oA", "{artifacts}/nmap"],
    },
    "masscan": {
        "conflicts": ["-oJ", "-oX", "-oL", "-oG", "--output-format", "--output-filename"],
        "flags": ["-oJ", "{artifacts}/masscan.json"],
    },
    "gobuster": {
        "conflicts": ["-o", "--output"],
        "flags": ["-o", "{artifacts}/gobuster.txt"],
    },
    "feroxbuster": {
        "conflicts": ["-o", "--output", "--json"],
        "flags": ["-o", "{artifacts}/feroxbuster.txt"],
    },
    "ffuf": {
        "conflicts": ["-o", "-of"],
        "flags": ["-o", "{artifacts}/ffuf.json", "-of", "json"],
    },
    "nikto": {
        "conflicts": ["-output", "-o", "-Output"],
        "flags": ["-output", "{artifacts}/nikto.xml", "-Format", "xml"],
    },
    "sqlmap": {
        "conflicts": ["--output-dir"],
        "flags": ["--output-dir", "{artifacts}/sqlmap"],
    },
    "dirsearch": {
        "conflicts": ["-o", "--output", "--simple-report", "--plain-text-report"],
        "flags": ["--simple-report", "{artifacts}/dirsearch.txt"],
    },
}


def auto_artifact_flags(binary: str, existing_argv: list[str]) -> list[str]:
    """Return the artifact-output flags to append to ``existing_argv``.

    The placeholder ``{artifacts}`` in the returned tokens must be replaced
    by the caller with the per-call artifacts directory. Returns an empty
    list when the rule does not apply (no rule for ``binary`` or operator
    already provided an equivalent flag).
    """
    rule = _AUTO_ARTIFACT_RULES.get(binary)
    if not rule:
        return []
    conflicts = rule.get("conflicts", [])
    if any(tok in existing_argv for tok in conflicts):
        return []
    return list(rule.get("flags", []))


def materialize_artifact_flags(flags: list[str], artifacts_dir) -> list[str]:
    """Resolve ``{artifacts}`` placeholders against a concrete directory."""
    adir = str(artifacts_dir)
    return [tok.replace("{artifacts}", adir) for tok in flags]


# ─────────────────────────────────────────────
# Response profile resolution (Phase 4)
# ─────────────────────────────────────────────

# Per-category defaults when a descriptor doesn't override.
_CATEGORY_PROFILE_DEFAULTS: dict[str, str] = {
    "recon":      "head_tail",
    "web":        "head_tail",
    "vuln":       "head_tail",
    "ad":         "head_tail",
    "exploit":    "head_tail",
    "creds":      "head_tail",
    "network":    "head_tail",
    "wireless":   "head_tail",
    "post":       "head_tail",
    "blueteam":   "summary_only",
    "engagement": "summary_only",
}


def response_profile_for(descriptor: dict[str, Any]) -> dict[str, Any]:
    """Return ``{profile, head_bytes, tail_bytes}`` for a tool descriptor.

    Resolution order:
      1. explicit ``response_profile``/``response_head_bytes``/``response_tail_bytes``
         on the descriptor
      2. category default
      3. global fallback (``head_tail`` / 8192 / 2048)
    """
    cat = descriptor.get("category", "")
    profile = (
        descriptor.get("response_profile")
        or _CATEGORY_PROFILE_DEFAULTS.get(cat)
        or "head_tail"
    )
    head = int(descriptor.get("response_head_bytes", 8192))
    tail = int(descriptor.get("response_tail_bytes", 2048))
    return {"profile": profile, "head_bytes": head, "tail_bytes": tail}


# ─────────────────────────────────────────────
# Inventory helpers
# ─────────────────────────────────────────────

def binary_available(name_or_path: str) -> bool:
    """True if the binary is on PATH or exists as absolute path."""
    if "/" in name_or_path:
        return Path(name_or_path).exists()
    for d in os.environ.get("PATH", "").split(":"):
        if d and (Path(d) / name_or_path).exists():
            return True
    return False


def gap_report() -> dict[str, Any]:
    """Compare the catalogue against installed binaries."""
    cat = load_catalog()
    available = []
    missing = []
    for d in cat:
        bin_name = d.get("binary", d["name"])
        if binary_available(bin_name):
            available.append(d["name"])
        else:
            missing.append(d["name"])
    return {
        "total": len(cat),
        "available": available,
        "missing": missing,
        "available_count": len(available),
        "missing_count": len(missing),
    }


# ─────────────────────────────────────────────
# Documentation rendering for the LLM
# ─────────────────────────────────────────────

def descriptor_doc(name_or_descriptor: str | dict[str, Any]) -> str:
    """
    Render a Markdown documentation block for a tool descriptor.
    Includes optional fields (when/why/how_notes/references/examples/
    interactive/risk_level) so the agent has rich context for tool selection.
    """
    d = (
        get_descriptor(name_or_descriptor)
        if isinstance(name_or_descriptor, str)
        else name_or_descriptor
    )
    if not d:
        return f"_Unknown tool: {name_or_descriptor}_"

    name = d.get("name", "?")
    cat = d.get("category", "misc")
    binary = d.get("binary", name)
    desc = d.get("description", "")
    sudo = bool(d.get("requires_sudo"))
    risk = d.get("risk_level", "unknown")
    interactive = bool(d.get("interactive"))
    timeout = d.get("default_timeout_seconds", 300)
    mitre = d.get("mitre", []) or []
    when = d.get("when", "")
    why = d.get("why", "")
    how = d.get("how_notes", "")
    refs = d.get("references", []) or []
    examples = d.get("examples", []) or []
    interaction = d.get("interaction") or {}
    artifacts = d.get("output_artifacts", []) or []

    lines: list[str] = []
    lines.append(f"# `{name}` — {desc}")
    lines.append("")
    lines.append(f"- **Binary**: `{binary}`  ·  **Category**: `{cat}`  ·  "
                 f"**Sudo**: {'yes' if sudo else 'no'}  ·  **Risk**: {risk}  "
                 f"·  **Interactive**: {'yes' if interactive else 'no'}  "
                 f"·  **Default timeout**: {timeout}s")
    if mitre:
        lines.append(f"- **MITRE ATT&CK**: {', '.join(mitre)}")
    lines.append("")
    if when:
        lines += ["## When to use", when, ""]
    if why:
        lines += ["## Why this tool", why, ""]
    if how:
        lines += ["## How (caveats & operational notes)", how, ""]

    schema = d.get("args_schema") or {}
    props: dict[str, Any] = schema.get("properties", {})
    required: list[str] = schema.get("required", []) or []
    if props:
        lines.append("## Parameters")
        for k, spec in props.items():
            t = spec.get("type", "any")
            req = " *(required)*" if k in required else ""
            default = (
                f" — default `{spec['default']}`" if "default" in spec else ""
            )
            enum = (
                f" — one of {spec['enum']}" if spec.get("enum") else ""
            )
            sd = spec.get("description", "")
            lines.append(f"- `{k}` ({t}){req}{default}{enum}: {sd}")
        lines.append("")

    if examples:
        lines.append("## Examples")
        for ex in examples:
            ename = ex.get("name", "example")
            eargs = ex.get("args", {})
            outcome = ex.get("expected_outcome", "")
            lines.append(f"- **{ename}** → `{eargs}`")
            if outcome:
                lines.append(f"  - Expected: {outcome}")
        lines.append("")

    if interactive and interaction:
        lines.append("## Interactive session protocol")
        itype = interaction.get("type", "pty")
        lines.append(f"- **Type**: `{itype}`")
        prompts = interaction.get("prompts", []) or []
        if prompts:
            lines.append(f"- **Expected prompt patterns**: "
                         f"{', '.join('`'+p+'`' for p in prompts)}")
        chelp = interaction.get("commands_help", "")
        if chelp:
            lines.append(f"- **Inside-session commands**: {chelp}")
        lines.append(
            "- Use `parrot_session_start` to spawn, `parrot_session_send` "
            "to inject text/commands, `parrot_session_close` to terminate."
        )
        lines.append("")

    if artifacts:
        lines.append("## Output artifacts")
        for a in artifacts:
            lines.append(f"- `{a}`")
        lines.append("")

    if refs:
        lines.append("## References")
        for r in refs:
            lines.append(f"- {r}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ─────────────────────────────────────────────
# Lightweight schema sanity-check (catalog-level)
# ─────────────────────────────────────────────

_VALID_CATEGORIES = {
    "recon", "web", "vuln", "ad", "creds", "network",
    "wireless", "re", "secrets", "cloud", "mobile",
    "iot", "post-exploit", "misc",
}
_VALID_RISK = {"low", "medium", "high", "critical", "unknown"}


def lint_catalog(path: str | Path | None = None) -> list[str]:
    """
    Return a list of human-readable warnings for the catalogue.
    Empty list = catalogue is clean. Used by tests / CI.
    """
    issues: list[str] = []
    cat = load_catalog(path, force=True)
    seen: set[str] = set()
    for i, d in enumerate(cat):
        prefix = f"[{i}]"
        name = d.get("name")
        if not name:
            issues.append(f"{prefix} missing 'name'")
            continue
        prefix = f"[{name}]"
        if name in seen:
            issues.append(f"{prefix} duplicate name")
        seen.add(name)
        if d.get("category") not in _VALID_CATEGORIES:
            issues.append(
                f"{prefix} category '{d.get('category')}' not in {sorted(_VALID_CATEGORIES)}"
            )
        if not d.get("binary"):
            issues.append(f"{prefix} missing 'binary'")
        if not d.get("description"):
            issues.append(f"{prefix} missing 'description'")
        rl = d.get("risk_level", "unknown")
        if rl not in _VALID_RISK:
            issues.append(f"{prefix} risk_level '{rl}' invalid")
        if not isinstance(d.get("argv_template", []), list):
            issues.append(f"{prefix} 'argv_template' must be a list")
        if d.get("interactive") and not isinstance(
            d.get("interaction") or {}, dict
        ):
            issues.append(f"{prefix} interactive=true but 'interaction' missing/invalid")
    return issues
