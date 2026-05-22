"""
core/tracking/events.py — Typed factories for v3.0 audit events.

Every factory returns a ready-to-write ``AuditEntry`` whose ``action`` is a
stable string from :class:`core.audit_events.AuditAction` and whose
``details`` payload carries a schema version (``"v": TRACKING_SCHEMA_V``)
plus event-specific fields.

The actual encrypted-at-rest concern (Fernet wrap for LLM prompt/response
payloads) lives in :mod:`core.tracking.encrypted_sink` — these factories
emit *plaintext* entries; the writer pipeline decides whether to encrypt.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from core.audit_events import TRACKING_SCHEMA_V, AuditAction
from core.models import AuditEntry


def prompt_hash(messages: list[dict[str, Any]] | str, *, system: str = "") -> str:
    """Compute a stable BLAKE2b-256 hex digest of a prompt payload.

    ``messages`` may be either the canonical JSON-friendly list passed to
    Anthropic / OpenAI-compatible APIs, or an already-rendered string. The
    optional ``system`` argument is concatenated first so that two prompts
    with identical message arrays but different system primes hash differently
    (which is what the replay machinery needs).
    """
    if isinstance(messages, str):
        payload = system + "\x1f" + messages  # ASCII unit-separator
    else:
        payload = system + "\x1f" + json.dumps(
            messages, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        )
    return hashlib.blake2b(payload.encode("utf-8"), digest_size=32).hexdigest()


def _make(
    action: AuditAction,
    engagement_id: str,
    *,
    target: str = "",
    actor: str = "agent",
    extra: dict[str, Any] | None = None,
) -> AuditEntry:
    details: dict[str, Any] = {"v": TRACKING_SCHEMA_V}
    if extra:
        details.update(extra)
    return AuditEntry(
        engagement_id=engagement_id or "-",
        actor=actor,
        action=str(action),
        target=target,
        details=details,
    )


# ── LLM I/O events ─────────────────────────────────────────────────────────


def make_llm_prompt_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    provider: str,
    model: str,
    prompt_hash_hex: str,
    messages_count: int,
    system_chars: int,
    tools_offered: int,
    temperature: float,
    seed: int | None,
    prompt_payload: str | None = None,
) -> AuditEntry:
    """Emitted just before a ``provider.chat`` call. ``prompt_payload`` is
    the raw prompt that the encrypted sink will Fernet-wrap; producers may
    pass ``None`` if they prefer hash-only auditing.
    """
    extra: dict[str, Any] = {
        "run_id": run_id,
        "role": role,
        "provider": provider,
        "model": model,
        "prompt_hash": prompt_hash_hex,
        "messages_count": messages_count,
        "system_chars": system_chars,
        "tools_offered": tools_offered,
        "temperature": temperature,
        "seed": seed,
    }
    if prompt_payload is not None:
        extra["prompt_payload"] = prompt_payload
    return _make(AuditAction.LLM_PROMPT_SENT, engagement_id, target=role, extra=extra)


def make_llm_response_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    provider: str,
    model: str,
    response_hash_hex: str,
    stop_reason: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: float,
    tool_calls_count: int,
    response_payload: str | None = None,
) -> AuditEntry:
    extra: dict[str, Any] = {
        "run_id": run_id,
        "role": role,
        "provider": provider,
        "model": model,
        "response_hash": response_hash_hex,
        "stop_reason": stop_reason,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": latency_ms,
        "tool_calls_count": tool_calls_count,
    }
    if response_payload is not None:
        extra["response_payload"] = response_payload
    return _make(AuditAction.LLM_RESPONSE_RECEIVED, engagement_id, target=role, extra=extra)


def make_llm_reasoning_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    reasoning_text: str | None,
    reasoning_chars: int,
    reasoning_source: str,
) -> AuditEntry:
    """``reasoning_source`` is ``"qwen_think"`` | ``"anthropic_thinking"`` |
    ``"openai_reasoning"`` — lets the dashboard render the right widget.
    """
    extra: dict[str, Any] = {
        "run_id": run_id,
        "role": role,
        "reasoning_chars": reasoning_chars,
        "reasoning_source": reasoning_source,
    }
    if reasoning_text is not None:
        extra["reasoning_text"] = reasoning_text
    return _make(AuditAction.LLM_REASONING, engagement_id, target=role, extra=extra)


# ── Agent-step (ReAct atomic) ──────────────────────────────────────────────


def make_agent_step_event(
    *,
    engagement_id: str,
    step_dump: dict[str, Any],
) -> AuditEntry:
    """``step_dump`` is the output of ``AgentStep.model_dump(mode='json')``."""
    target = str(step_dump.get("role", ""))
    return _make(
        AuditAction.AGENT_STEP,
        engagement_id,
        target=target,
        extra={"step": step_dump},
    )


# ── Role / phase / state lifecycle ─────────────────────────────────────────


def make_role_handoff_event(
    *,
    engagement_id: str,
    run_id: str,
    src_role: str,
    dst_role: str,
    handoff_reason: str,
    context_ref: str,
) -> AuditEntry:
    """``context_ref`` is the storage handle (path/URI) of the full
    ``AgentContext`` snapshot — kept out of the audit payload itself to
    bound entry size.
    """
    return _make(
        AuditAction.ROLE_HANDOFF,
        engagement_id,
        target=f"{src_role}->{dst_role}",
        extra={
            "run_id": run_id,
            "src_role": src_role,
            "dst_role": dst_role,
            "reason": handoff_reason,
            "context_ref": context_ref,
        },
    )


def make_phase_transition_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    src_phase: str,
    dst_phase: str,
    reason: str = "",
) -> AuditEntry:
    return _make(
        AuditAction.PHASE_TRANSITION,
        engagement_id,
        target=f"{src_phase}->{dst_phase}",
        extra={
            "run_id": run_id,
            "role": role,
            "src_phase": src_phase,
            "dst_phase": dst_phase,
            "reason": reason,
        },
    )


def make_reflection_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    step_id: str,
    reflection_text: str | None,
    reflection_chars: int,
    mode: str,
) -> AuditEntry:
    """``mode`` is ``"sync"`` | ``"async"`` | ``"off"``."""
    extra: dict[str, Any] = {
        "run_id": run_id,
        "role": role,
        "step_id": step_id,
        "reflection_chars": reflection_chars,
        "mode": mode,
    }
    if reflection_text is not None:
        extra["reflection_text"] = reflection_text
    return _make(AuditAction.REFLECTION_COMPLETED, engagement_id, target=role, extra=extra)


def make_state_transition_event(
    *,
    engagement_id: str,
    run_id: str,
    role: str,
    src_state: str,
    dst_state: str,
    reason: str = "",
) -> AuditEntry:
    return _make(
        AuditAction.STATE_TRANSITION,
        engagement_id,
        target=f"{src_state}->{dst_state}",
        extra={
            "run_id": run_id,
            "role": role,
            "src_state": src_state,
            "dst_state": dst_state,
            "reason": reason,
        },
    )
