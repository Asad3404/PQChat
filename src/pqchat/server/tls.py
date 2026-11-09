"""Serve an ASGI app over TLS 1.3 only (SR-23, M7).

uvicorn has no option for a minimum TLS version, so we build its config, let it create the SSL
context, and then raise ``minimum_version`` to TLS 1.3 before serving. TLS 1.3 removes static-RSA
and CBC suites and always provides forward secrecy for the transport layer. (The transport is a
second layer only: message confidentiality never depends on it.)
"""

from __future__ import annotations

import ssl

import uvicorn


def configure(config: uvicorn.Config) -> None:
    config.load()
    if config.ssl is not None:
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
        config.ssl.maximum_version = ssl.TLSVersion.TLSv1_3


def serve(
    app: str,
    *,
    host: str,
    port: int,
    certfile: str | None,
    keyfile: str | None,
    ws_max_size: int,
) -> None:
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        server_header=False,
        log_level="warning",
        ws_max_size=ws_max_size,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )
    configure(config)
    uvicorn.Server(config).run()
