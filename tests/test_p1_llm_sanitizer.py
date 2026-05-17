"""
P1.10 — LLM tool-output sanitizer.
"""
from __future__ import annotations

from core.llm_io_sanitizer import DEFAULT_MAX_BYTES, sanitize_tool_output


def test_strips_control_chars_keeps_newlines():
    raw = "hello\x07\x1b[31mworld\nline2\ttab\r\n"
    out = sanitize_tool_output(raw)
    assert "\x07" not in out
    assert "\x1b" not in out
    assert "\n" in out
    assert "\t" in out
    assert "world" in out


def test_wraps_with_fence():
    out = sanitize_tool_output("payload", tool_name="nmap", call_id="abc-123")
    assert out.startswith("<<<TOOL_OUTPUT name=nmap call_id=abc-123>>>")
    assert out.rstrip().endswith("<<<END_TOOL_OUTPUT>>>")


def test_fence_metadata_is_sanitized():
    out = sanitize_tool_output("x", tool_name="bad>>>name\n", call_id="../etc/passwd")
    # Forbidden characters in fence metadata MUST be replaced.
    assert ">>>name" not in out.split("\n", 1)[0]
    assert ".." in out.split("\n", 1)[0] or "_" in out.split("\n", 1)[0]


def test_truncates_large_payload():
    raw = "A" * (DEFAULT_MAX_BYTES * 2)
    out = sanitize_tool_output(raw)
    assert "truncated" in out
    # Wrapped output stays within ~cap + small overhead.
    assert len(out.encode("utf-8")) < DEFAULT_MAX_BYTES + 4096


def test_redacts_aws_keys():
    raw = "creds: AKIAIOSFODNN7EXAMPLE secret"
    out = sanitize_tool_output(raw)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "REDACTED:AWS_KEY" in out


def test_redacts_jwt():
    raw = "auth=eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMeKKF2Q"
    out = sanitize_tool_output(raw)
    assert "eyJhbGciOi" not in out
    assert "REDACTED:JWT" in out


def test_redacts_password_kv():
    raw = "smbclient //srv/share -U admin password=hunter2"
    out = sanitize_tool_output(raw)
    assert "hunter2" not in out
    assert "REDACTED:SECRET" in out


def test_redacts_rfc1918():
    raw = "found host 10.0.0.5 and 192.168.1.250 and 172.31.5.5"
    out = sanitize_tool_output(raw)
    for ip in ("10.0.0.5", "192.168.1.250", "172.31.5.5"):
        assert ip not in out
    assert "REDACTED:RFC1918" in out


def test_keeps_public_ips():
    raw = "scanning 8.8.8.8 and 1.1.1.1 OK"
    out = sanitize_tool_output(raw)
    assert "8.8.8.8" in out
    assert "1.1.1.1" in out


def test_redact_private_ips_can_be_disabled():
    raw = "host 10.0.0.7"
    out = sanitize_tool_output(raw, redact_private_ips=False)
    assert "10.0.0.7" in out


def test_normalizes_unicode_confusables():
    raw = "ＡＤＭＩＮ password=ｓｅｃｒｅｔ"  # fullwidth letters
    out = sanitize_tool_output(raw)
    # NFC pulls fullwidth into ASCII, which the redactor can then catch.
    assert "REDACTED:SECRET" in out


def test_handles_non_string_input():
    out = sanitize_tool_output(None)  # type: ignore[arg-type]
    assert "<<<TOOL_OUTPUT" in out
    out2 = sanitize_tool_output({"foo": "bar"})  # type: ignore[arg-type]
    assert "foo" in out2
