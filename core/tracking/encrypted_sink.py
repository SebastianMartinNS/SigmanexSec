"""
core/tracking/encrypted_sink.py — Confidentiality wrapper for v3.0 audit
payloads.

The BLAKE2b hash-chain in :mod:`core.audit_log` already gives *tamper
evidence*. This sink adds *confidentiality* for the cognitive-tracking
payloads that carry the raw prompt / response / reasoning of the LLM —
data that an attacker who reads the JSONL on disk should not be able to
decrypt without the operator key.

Design constraints
------------------

* **No new env vars**: the sink reuses the credential-encryption material
  that :mod:`core.session_store` already requires the operator to provide
  (``CREDENTIAL_ENCRYPTION_PASSPHRASE`` or ``CREDENTIAL_ENCRYPTION_KEY``).
  An operator who has already configured at-rest encryption for stored
  credentials automatically gets encrypted prompt audit too.

* **Opt-out for dev**: ``SAP_AUDIT_ENCRYPT=0`` disables the wrap. Useful
  for local engagement replay where the operator wants to grep the audit
  log directly.

* **Override key**: ``SAP_AUDIT_FERNET_KEY`` (base64 32-byte) replaces the
  derived key. Useful when the auditor wants a key that is *separate* from
  the credential-store key (KMS-injected, rotated independently).

* **Chain-safe**: only specific ``details`` keys are wrapped — never the
  envelope (``action``, ``engagement_id``, ``timestamp``, ...) — so
  ``verify_audit_chain`` still re-walks the BLAKE2b chain without the key.

Public API
----------

``EncryptedAuditEnvelope`` is the structural marker for an encrypted blob
inside ``details``. ``encrypt_fields(entry, fields=(...))`` mutates a
ready-to-write ``AuditEntry`` in place, replacing each plaintext field
with an envelope. ``decrypt_fields(obj)`` is the inverse, used by the
dashboard/replay reader.
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

from core.models import AuditEntry

_log = logging.getLogger(__name__)

_FERNET_ENV = "SAP_AUDIT_FERNET_KEY"
_DISABLE_ENV = "SAP_AUDIT_ENCRYPT"

# Marker prefix so a reader can recognize an encrypted blob without needing
# the key. The envelope dict form is preferred (richer metadata), but the
# string form is what we store on disk after json.dumps round-trips.
ENVELOPE_PREFIX = "sap-enc:v1:"

# Cache of the Fernet instance (or None when encryption is disabled).
_FERNET_CACHE: Any | None = None
_FERNET_DISABLED = False


def _encrypt_disabled() -> bool:
    return os.environ.get(_DISABLE_ENV, "1") in ("", "0", "false", "False")


def _derive_audit_key() -> bytes | None:
    """Return a 32-byte Fernet key bytes (base64-url-safe).

    Resolution order:
      1. ``SAP_AUDIT_FERNET_KEY`` (raw base64-urlsafe 32-byte)
      2. The credential-store key (``core.session_store._derive_key``)
         re-encoded as base64-urlsafe.

    Returns ``None`` if neither source resolves — the sink then degrades
    to pass-through and logs a warning once.
    """
    direct = os.environ.get(_FERNET_ENV, "").strip()
    if direct:
        try:
            # Validate by attempting a Fernet constructor; raises on bad shape.
            from cryptography.fernet import Fernet
            Fernet(direct.encode())
            return direct.encode()
        except Exception as exc:
            _log.warning(
                "SAP_AUDIT_FERNET_KEY set but invalid (%s); falling back", exc,
            )

    try:
        from core.session_store import _derive_key  # type: ignore[attr-defined]
        raw = _derive_key()
        if not raw or len(raw) < 32:
            return None
        return base64.urlsafe_b64encode(raw[:32])
    except Exception as exc:
        _log.warning("audit Fernet key derivation failed: %s", exc)
        return None


def _get_fernet() -> Any | None:
    global _FERNET_CACHE, _FERNET_DISABLED
    if _FERNET_DISABLED:
        return None
    if _FERNET_CACHE is not None:
        return _FERNET_CACHE
    if _encrypt_disabled():
        _FERNET_DISABLED = True
        return None
    key = _derive_audit_key()
    if key is None:
        _FERNET_DISABLED = True
        return None
    try:
        from cryptography.fernet import Fernet
        _FERNET_CACHE = Fernet(key)
        return _FERNET_CACHE
    except Exception as exc:
        _log.warning("audit Fernet init failed: %s", exc)
        _FERNET_DISABLED = True
        return None


def _is_envelope(value: Any) -> bool:
    if isinstance(value, str) and value.startswith(ENVELOPE_PREFIX):
        return True
    if isinstance(value, dict) and value.get("__sap_enc__") == "v1":
        return True
    return False


def encrypt_value(value: Any) -> str | Any:
    """Encrypt a single ``details`` field. Returns the original value when
    encryption is disabled (so the audit chain still works in dev mode)."""
    f = _get_fernet()
    if f is None:
        return value
    if value is None:
        return None
    if _is_envelope(value):
        return value  # idempotent
    try:
        if not isinstance(value, str):
            import json
            value_str = json.dumps(value, ensure_ascii=False)
            scheme = "json"
        else:
            value_str = value
            scheme = "str"
        token = f.encrypt(value_str.encode("utf-8")).decode("ascii")
        return f"{ENVELOPE_PREFIX}{scheme}:{token}"
    except Exception as exc:
        _log.warning("encrypt_value failed: %s", exc)
        return value


def decrypt_value(value: Any) -> Any:
    """Inverse of :func:`encrypt_value`. Returns the original value when
    decryption is disabled (so reader code can degrade gracefully)."""
    if not _is_envelope(value):
        return value
    f = _get_fernet()
    if f is None:
        return value  # cannot decrypt without key
    try:
        if isinstance(value, dict):
            scheme = value.get("scheme", "str")
            token = value.get("token", "")
        else:
            payload = value[len(ENVELOPE_PREFIX):]
            scheme, _, token = payload.partition(":")
        plain = f.decrypt(token.encode("ascii")).decode("utf-8")
        if scheme == "json":
            import json
            return json.loads(plain)
        return plain
    except Exception as exc:
        _log.warning("decrypt_value failed: %s", exc)
        return value


# Default set of details fields that carry sensitive plaintext. The v3
# factories in :mod:`core.tracking.events` use these names verbatim.
DEFAULT_ENCRYPTED_FIELDS: tuple[str, ...] = (
    "prompt_payload",
    "response_payload",
    "reasoning_text",
    "reflection_text",
)


def encrypt_entry_in_place(
    entry: AuditEntry,
    *,
    fields: tuple[str, ...] = DEFAULT_ENCRYPTED_FIELDS,
) -> AuditEntry:
    """Encrypt the specified ``details`` keys on ``entry`` in place.

    Returns the same entry for convenient chaining. Safe to call when
    encryption is disabled (no-op). Safe to call twice (envelopes are
    idempotent).
    """
    details = entry.details
    if not isinstance(details, dict):
        return entry
    for name in fields:
        if name in details and details[name] is not None:
            details[name] = encrypt_value(details[name])
    return entry


def decrypt_entry(obj: dict[str, Any]) -> dict[str, Any]:
    """Pure-dict variant for replay readers. Mutates a copy and returns it."""
    out = dict(obj)
    details = out.get("details")
    if isinstance(details, dict):
        new_details = dict(details)
        for k, v in list(new_details.items()):
            if _is_envelope(v):
                new_details[k] = decrypt_value(v)
        out["details"] = new_details
    return out
