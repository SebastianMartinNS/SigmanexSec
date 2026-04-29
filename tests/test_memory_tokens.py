from __future__ import annotations

from core.memory.tokens import count_message_tokens, count_tokens


def test_count_tokens_empty():
    assert count_tokens("") == 0


def test_count_tokens_nonempty():
    assert count_tokens("hello world") > 0


def test_count_message_tokens_handles_tool_calls():
    msgs = [
        {"role": "system", "content": "You are helpful"},
        {"role": "user", "content": "ping"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "1", "function": {"name": "noop", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_call_id": "1", "content": "ok"},
    ]
    n = count_message_tokens(msgs)
    assert n > 0
