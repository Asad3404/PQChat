"""Logging that cannot leak secrets (SR-25, CLAUDE.md §3.4).

``RedactingFilter`` rewrites every log record before it is emitted:

* any ``bytes`` / ``bytearray`` / ``memoryview`` argument becomes ``<redacted N bytes>``;
* any run of 32+ hex characters or 32+ base64/base64url characters in the formatted message
  is replaced, which catches keys, ciphertexts and tokens that were turned into text first.

Use ``get_logger(__name__)`` everywhere instead of ``logging.getLogger``.
"""

from __future__ import annotations

import logging
import re

_LONG_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}")


def _redact_value(value: object) -> object:
    if isinstance(value, bytes | bytearray | memoryview):
        return f"<redacted {len(value)} bytes>"
    return value


def redact_text(text: str) -> str:
    return _LONG_TOKEN.sub(lambda m: f"<redacted {len(m.group(0))} chars>", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, dict):
            record.args = {k: _redact_value(v) for k, v in record.args.items()}
        elif record.args:
            record.args = tuple(_redact_value(a) for a in record.args)
        message = record.getMessage()
        record.msg = redact_text(message)
        record.args = None
        return True


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
