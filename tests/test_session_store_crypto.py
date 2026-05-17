from __future__ import annotations

import pytest

from core.session_store import _decrypt, _derive_key, _encrypt


def test_pbkdf2_key_derivation_is_stable(tmp_paths, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "correct horse battery staple")
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    from core import session_store

    session_store._KEY_CACHE = None
    k1 = _derive_key()
    session_store._KEY_CACHE = None
    k2 = _derive_key()
    assert k1 == k2
    assert len(k1) == 32
    assert k1 != b"SAP_DEV_KEY_CHANGE_ME_IN_PROD!!"


def test_passphrase_change_changes_key(tmp_paths, monkeypatch):
    from core import session_store

    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "first")
    session_store._KEY_CACHE = None
    k1 = _derive_key()
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "second")
    session_store._KEY_CACHE = None
    k2 = _derive_key()
    assert k1 != k2


def test_roundtrip_encrypt_decrypt(tmp_paths, monkeypatch):
    monkeypatch.setenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", "lab-test-pass")
    from core import session_store

    session_store._KEY_CACHE = None
    ct = _encrypt("hunter2")
    assert ct and ct != "hunter2"
    assert _decrypt(ct) == "hunter2"


def test_decrypt_garbage_returns_marker():
    assert _decrypt("not-hex") == "[DECRYPTION_FAILED]"
    assert _decrypt("") == ""


def test_fail_fast_when_no_key_and_not_dev(tmp_paths, monkeypatch):
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", raising=False)
    monkeypatch.delenv("SAP_DEV_MODE", raising=False)
    from core import session_store

    session_store._KEY_CACHE = None
    with pytest.raises(RuntimeError):
        _derive_key()


def test_dev_mode_uses_legacy_key_with_warning(tmp_paths, monkeypatch, caplog):
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("CREDENTIAL_ENCRYPTION_PASSPHRASE", raising=False)
    monkeypatch.setenv("SAP_DEV_MODE", "1")
    from core import session_store

    session_store._KEY_CACHE = None
    with caplog.at_level("WARNING"):
        k = _derive_key()
    assert k == b"SAP_DEV_KEY_CHANGE_ME_IN_PROD!!"
    assert any("SAP_DEV_MODE" in r.message for r in caplog.records)
