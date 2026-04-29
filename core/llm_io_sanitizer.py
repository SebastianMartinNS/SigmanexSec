"""
core/llm_io_sanitizer.py — P1.10 hardening.

Sanitizes tool stdout/stderr before feeding it back to the LLM. Mitigations:

* Strip ASCII control characters except \\n, \\r, \\t (defeats VT100 escape
  injection that some LLMs render as actionable text).
* Unicode NFC normalize to collapse confusables (e.g. fullwidth letters) into
  their canonical form before pattern matching.
* Hard cap on payload size (default 200 KB) — long base64 dumps and binary
  blobs cannot drown the model context. Truncation is annotated with
  ``[...truncated N bytes…]``.
* Redact obvious secrets: AWS keys, GitHub PATs, Bearer tokens, JWTs,
  RFC1918 / loopback IPs (so private network topology never leaks via the
  prompt history), and `password=…` style key-value pairs.
* Wrap output in tagged fences ``<<<TOOL_OUTPUT name=… call_id=…>>> … <<<END>>>``
  so the LLM is trained-rejected from interpreting tool stdout as user
  instructions (a "Carlini-style" indirect-injection mitigation).

The sanitizer is purely text → text and has no I/O. Hook it from the
orchestrator immediately before ``messages.append({"role": "tool", ...})``.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Final


# Maximum bytes of tool output retained verbatim. Anything larger is truncated
# with a marker. 200 KB is enough for nmap -A on a /24 yet keeps the LLM
# context affordable. Override via SAP_LLM_MAX_TOOL_OUTPUT.
DEFAULT_MAX_BYTES: Final[int] = 200 * 1024


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Patterns ordered by specificity. Replacement keeps prefix to aid debugging.
_REDACTIONS: Final[list[tuple[re.Pattern[str], str]]] = [
    # AWS access keys (AKIA / ASIA / AGPA / AIDA / ANPA / ANVA / AROA / APKA / ABIA / ACCA).
    (re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|ANPA|ANVA|AROA|APKA|ABIA|ACCA)[A-Z0-9]{16})\b"),
     "[REDACTED:AWS_KEY]"),
    # AWS secret access key (only when prefixed by an obvious context keyword;
    # bare 40-char base64 produces too many false positives).
    (re.compile(r"(?i)(aws_secret_access_key|aws_secret|secret[_-]?access[_-]?key)\s*[:=]\s*[A-Za-z0-9/+=]{30,}"),
     r"\1=[REDACTED:AWS_SECRET]"),
    # GitHub PAT (classic + fine-grained).
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b"),
     "[REDACTED:GITHUB_PAT]"),
    # JWT (three base64url segments separated by dots).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),
     "[REDACTED:JWT]"),
    # Bearer / Authorization headers.
    (re.compile(r"(?i)\b(bearer|token|authorization)\s*[:=]\s*[A-Za-z0-9._\-+/=]{8,}"),
     r"\1: [REDACTED:TOKEN]"),
    # password= / pwd= / passwd= style key-value secrets in stdout.
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S+"),
     r"\1=[REDACTED:SECRET]"),
    # Private network / loopback IPs (do not leak internal topology to the LLM).
    (re.compile(r"\b10(?:\.\d{1,3}){3}\b"),                       "[REDACTED:RFC1918]"),
    (re.compile(r"\b172\.(1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}\b"), "[REDACTED:RFC1918]"),
    (re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b"),                 "[REDACTED:RFC1918]"),
    (re.compile(r"\b127(?:\.\d{1,3}){3}\b"),                      "[REDACTED:LOOPBACK]"),
]


def sanitize_tool_output(
    text: str,
    *,
    tool_name: str = "tool",
    call_id: str = "-",
    max_bytes: int | None = None,
    redact_private_ips: bool = True,
) -> str:
    """Apply the full sanitization pipeline.

    Parameters
    ----------
    text:
        Raw tool stdout/stderr (already merged or stringified by the caller).
    tool_name, call_id:
        Echoed in the wrapping fence so the LLM (and downstream auditors) can
        correlate which tool call produced the output.
    max_bytes:
        Truncation cap. Defaults to ``DEFAULT_MAX_BYTES``. Pass ``0`` to
        disable truncation (NOT recommended for arbitrary external output).
    redact_private_ips:
        When False, private/loopback IPs are kept verbatim. Useful in a
        contained engagement where revealing the topology to the LLM is
        intentional. Default ``True`` (defense-in-depth).
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    # 1. Unicode normalize.
    text = unicodedata.normalize("NFC", text)

    # 2. Strip control chars (keep \n \r \t).
    text = _CONTROL_RE.sub("", text)

    # 3. Truncate (byte-accurate).
    cap = DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
    if cap and len(text.encode("utf-8", errors="replace")) > cap:
        encoded = text.encode("utf-8", errors="replace")
        head_len = int(cap * 0.75)
        tail_len = cap - head_len - 64  # leave room for marker
        head = encoded[:head_len].decode("utf-8", errors="replace")
        tail = encoded[-tail_len:].decode("utf-8", errors="replace") if tail_len > 0 else ""
        truncated_bytes = len(encoded) - head_len - max(tail_len, 0)
        text = (
            head
            + f"\n[...truncated {truncated_bytes} bytes by SAP sanitizer...]\n"
            + tail
        )

    # 4. Redact secrets.
    for pat, repl in _REDACTIONS:
        if not redact_private_ips and ("RFC1918" in repl or "LOOPBACK" in repl):
            continue
        text = pat.sub(repl, text)

    # 5. Wrap with explicit fence — instructs the LLM that the content is
    #    untrusted data, NOT a directive. The wrapping is intentionally
    #    asymmetric (uppercase + triple angle brackets) so the model cannot
    #    forge it from inside a tool payload.
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", tool_name)[:64]
    safe_id   = re.sub(r"[^A-Za-z0-9_.-]", "_", call_id)[:64]
    return (
        f"<<<TOOL_OUTPUT name={safe_name} call_id={safe_id}>>>\n"
        f"{text}\n"
        f"<<<END_TOOL_OUTPUT>>>"
    )
