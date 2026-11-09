"""SR-23: the relay speaks TLS 1.3 only; the client verifies the certificate."""

from __future__ import annotations

import asyncio
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from pqchat.client.relay_client import RelayClient
from pqchat.client.tls import client_context
from pqchat.protocol.bundle import IdentityKeys
from pqchat.server import tls
from pqchat.server.app import create_app
from pqchat.server.devcerts import make
from tests.relay_harness import free_port


@pytest.fixture(scope="module")
def tls_relay(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    certs = tmp_path_factory.mktemp("certs")
    make(certs, "localhost")
    port = free_port()
    cfg = uvicorn.Config(
        create_app(),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ssl_certfile=str(certs / "relay.crt"),
        ssl_keyfile=str(certs / "relay.key"),
    )
    tls.configure(cfg)
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)
    yield port, certs
    server.should_exit = True
    t.join(5)


def test_tls13_client_connects(tls_relay) -> None:  # type: ignore[no-untyped-def]
    port, certs = tls_relay

    async def go() -> None:
        c = RelayClient(
            f"wss://localhost:{port}/ws",
            "alice",
            IdentityKeys.generate(),
            client_context(str(certs / "ca.crt")),
        )
        await c.connect(register=True)
        await c.close()

    asyncio.run(go())
    ctx = client_context(str(certs / "ca.crt"))
    with (
        socket.create_connection(("localhost", port)) as raw,
        ctx.wrap_socket(raw, server_hostname="localhost") as s,
    ):
        assert s.version() == "TLSv1.3"


def test_tls12_is_refused(tls_relay) -> None:  # type: ignore[no-untyped-def]
    port, certs = tls_relay
    ctx = ssl.create_default_context(cafile=str(certs / "ca.crt"))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("localhost", port)) as raw, pytest.raises(ssl.SSLError):
        ctx.wrap_socket(raw, server_hostname="localhost")


def test_untrusted_certificate_is_refused(tls_relay, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    port, _ = tls_relay
    make(tmp_path, "localhost")  # a different CA (e.g. a MITM proxy)
    ctx = client_context(str(tmp_path / "ca.crt"))
    with (
        socket.create_connection(("localhost", port)) as raw,
        pytest.raises(ssl.SSLCertVerificationError),
    ):
        ctx.wrap_socket(raw, server_hostname="localhost")


def test_devcerts_is_idempotent(tmp_path: Path) -> None:
    make(tmp_path, "relay")
    first = (tmp_path / "relay.crt").read_bytes()
    make(tmp_path, "relay")
    assert (tmp_path / "relay.crt").read_bytes() == first
