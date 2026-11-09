"""SR-25 / CLAUDE.md §3.4: secrets never reach log output."""

from __future__ import annotations

import base64
import logging
import os

import pytest

from pqchat.logsafe import get_logger, redact_text


def test_bytes_arguments_are_redacted(caplog: pytest.LogCaptureFixture) -> None:
    log = get_logger("pqchat.test1")
    key = os.urandom(32)
    with caplog.at_level(logging.INFO, logger="pqchat.test1"):
        log.info("derived key %s for %s", key, "bob")
        log.info("buffer %r", bytearray(key))
    text = caplog.text
    assert key.hex() not in text
    assert "<redacted 32 bytes>" in text
    assert "bob" in text


def test_hex_and_base64_strings_are_redacted(caplog: pytest.LogCaptureFixture) -> None:
    log = get_logger("pqchat.test2")
    secret = os.urandom(48)
    with caplog.at_level(logging.INFO, logger="pqchat.test2"):
        log.info("hex=%s", secret.hex())
        log.info("b64=" + base64.urlsafe_b64encode(secret).decode())
        log.info("dict %(k)s", {"k": secret})
    assert secret.hex() not in caplog.text
    assert base64.urlsafe_b64encode(secret).decode() not in caplog.text
    assert caplog.text.count("<redacted") == 3


def test_short_words_are_kept() -> None:
    assert redact_text("user alice sent 3 messages") == "user alice sent 3 messages"


def test_filter_is_added_once() -> None:
    a = get_logger("pqchat.test3")
    b = get_logger("pqchat.test3")
    assert a is b and len(a.filters) == 1
