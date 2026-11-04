"""Milestone 0: the relay stub starts and answers its health check.

We run the real uvicorn server on a free localhost port and talk to it with the
standard library, so no extra HTTP-client dependency is needed.
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest
import uvicorn

from pqchat.server.app import app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def relay_url() -> Iterator[str]:
    port = _free_port()
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", server_header=False
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            pytest.fail("relay did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _get(url: str) -> tuple[int, dict[str, str], bytes]:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 - fixed localhost URL
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def test_healthz(relay_url: str) -> None:
    status, _, body = _get(f"{relay_url}/healthz")
    assert status == 200
    assert json.loads(body) == {
        "status": "ok",
        "service": "pqchat-relay",
        "protocol_version": 1,
    }


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_documentation_is_not_exposed(relay_url: str, path: str) -> None:
    status, _, _ = _get(f"{relay_url}{path}")
    assert status == 404


def test_server_header_is_not_sent(relay_url: str) -> None:
    _, headers, _ = _get(f"{relay_url}/healthz")
    assert "server" not in {k.lower() for k in headers}
