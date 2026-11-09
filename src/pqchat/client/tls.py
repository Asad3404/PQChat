"""TLS 1.3-only client context for the relay connection (SR-23)."""

from __future__ import annotations

import ssl


def client_context(ca_file: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)  # verifies certificate and hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx
