"""The container health check works with and without TLS (and fails when nothing listens)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
import uvicorn

from pqchat.server import healthcheck, tls
from pqchat.server.app import create_app
from pqchat.server.devcerts import make
from tests.relay_harness import free_port, running_relay


def test_plain_http(monkeypatch: pytest.MonkeyPatch) -> None:
    with running_relay() as (addr, _):
        monkeypatch.setenv("PQCHAT_RELAY_PORT", addr.split(":")[1])
        monkeypatch.delenv("PQCHAT_TLS_CERT", raising=False)
        assert healthcheck.main() == 0


def test_nothing_listening(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQCHAT_RELAY_PORT", str(free_port()))
    monkeypatch.delenv("PQCHAT_TLS_CERT", raising=False)
    assert healthcheck.main() == 1


def test_tls_with_certificate_verification(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    make(tmp_path, "relay")
    port = free_port()
    cfg = uvicorn.Config(
        create_app(),
        host="127.0.0.1",
        port=port,
        log_level="warning",
        ssl_certfile=str(tmp_path / "relay.crt"),
        ssl_keyfile=str(tmp_path / "relay.key"),
    )
    tls.configure(cfg)
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)
    try:
        monkeypatch.setenv("PQCHAT_RELAY_PORT", str(port))
        monkeypatch.setenv("PQCHAT_TLS_CERT", str(tmp_path / "relay.crt"))
        assert healthcheck.main() == 0
    finally:
        server.should_exit = True
        t.join(5)
