"""SR-28 / SR-29: the local UI cannot be driven by other websites or local users (T-29..T-31)."""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

from pqchat.client.app import STATIC, create_ui
from pqchat.client.core import ChatClient
from tests.relay_harness import free_port

TOKEN = "t" * 43


@pytest.fixture(scope="module")
def ui(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    port = free_port()
    client = ChatClient(tmp_path_factory.mktemp("ui"), "ws://127.0.0.1:1/ws")
    app = create_ui(client, TOKEN, {f"127.0.0.1:{port}"})
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.02)
    yield f"127.0.0.1:{port}"
    server.should_exit = True
    t.join(5)


def call(
    addr: str, path: str, headers: dict[str, str] | None = None, body: dict | None = None
) -> tuple[int, dict[str, str], bytes]:  # type: ignore[type-arg]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{addr}{path}", data=data, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - localhost test server
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_valid_request(ui: str) -> None:
    status, headers, body = call(ui, "/api/status", {"X-PQChat-Token": TOKEN})
    assert status == 200 and json.loads(body)["locked"] is True
    csp = headers["content-security-policy"]
    assert (
        "script-src 'self'" in csp
        and "unsafe-inline" not in csp
        and "frame-ancestors 'none'" in csp
    )
    assert headers["x-content-type-options"] == "nosniff"


def test_missing_or_wrong_token(ui: str) -> None:
    assert call(ui, "/api/status")[0] == 401
    assert call(ui, "/api/status", {"X-PQChat-Token": "x" * 43})[0] == 401


def test_dns_rebinding_host_is_refused(ui: str) -> None:
    status, _, _ = call(ui, "/api/status", {"X-PQChat-Token": TOKEN, "Host": "evil.example:80"})
    assert status == 421
    assert call(ui, "/", {"Host": "evil.example"})[0] == 421


def test_cross_origin_request_is_refused(ui: str) -> None:
    headers = {"X-PQChat-Token": TOKEN, "Origin": "https://evil.example"}
    assert call(ui, "/api/status", headers)[0] == 403


def test_unlock_validation_and_wrong_passphrase(ui: str, tmp_path: Path) -> None:
    h = {"X-PQChat-Token": TOKEN}
    assert call(ui, "/api/unlock", h, {"username": "A B", "passphrase": "x" * 12})[0] == 422
    assert call(ui, "/api/unlock", h, {"username": "alice", "passphrase": "short"})[0] == 422


def test_static_files_only_whitelisted(ui: str) -> None:
    assert call(ui, "/static/app.js")[0] == 200
    assert call(ui, "/static/../core.py")[0] == 404
    assert call(ui, "/static/keystore.pqks")[0] == 404


def test_frontend_never_injects_html() -> None:
    """SR-29: no innerHTML, no inline handlers or scripts, nothing from other origins."""
    js = (STATIC / "app.js").read_text()
    html = (STATIC / "index.html").read_text()
    assert not re.search(
        r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", js
    )
    assert not re.search(r"\son[a-z]+=|<script>|style=", html)
    assert not re.search(r"https?://", html.replace("http://www.w3.org", ""))
