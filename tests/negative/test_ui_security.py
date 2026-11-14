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


def test_unlock_form_never_puts_the_passphrase_in_a_url() -> None:
    """ZAP finding 10024 (M8): a method-less form submits fields as a GET query string."""
    html = (STATIC / "index.html").read_text()
    form = re.search(r'<form id="unlock-form"[^>]*>', html)
    assert form is not None and 'method="post"' in form.group(0)


def test_post_to_root_does_not_accept_form_data(ui: str) -> None:
    status, _, _ = call(ui, "/", {}, {"username": "x", "passphrase": "y"})
    assert status == 405


def test_relay_errors_map_to_meaningful_status_codes(tmp_path: Path) -> None:
    """ZAP finding (M8): 'user does not exist' must not look like a server failure."""
    import asyncio

    from pqchat.client.app import create_ui as _create
    from pqchat.client.relay_client import RelayError

    client = ChatClient(tmp_path, "ws://127.0.0.1:1/ws")
    app = _create(client, TOKEN, {"x"})
    assert app is not None
    from fastapi import HTTPException

    def status(code: str) -> int:
        async def boom(*_: object) -> None:
            raise RelayError(code)

        client.send_text = boom  # type: ignore[method-assign]
        route = next(r for r in app.routes if getattr(r, "path", "") == "/api/chat/{name}/send")
        try:
            asyncio.run(route.endpoint(name="bob", body=type("B", (), {"text": "hi"})()))  # type: ignore[attr-defined]
        except HTTPException as e:
            return e.status_code
        return 200

    assert status("unknown_user") == 404
    assert status("no_bundle") == 404
    assert status("rate_limited") == 429
    assert status("connection_closed") == 502


def test_second_unlock_is_refused(tmp_path: Path) -> None:
    """ZAP finding (M8): /api/unlock must not reload state or reconnect once unlocked."""
    import asyncio

    from fastapi import HTTPException

    client = ChatClient(tmp_path, "ws://127.0.0.1:1/ws")
    client.unlock("alice", "correct horse battery staple")
    app = create_ui(client, TOKEN, {"x"})
    route = next(r for r in app.routes if getattr(r, "path", "") == "/api/unlock")
    body = type("B", (), {"username": "mallory", "passphrase": "another passphrase"})()
    try:
        asyncio.run(route.endpoint(body=body))  # type: ignore[attr-defined]
    except HTTPException as e:
        assert e.status_code == 409
    else:
        raise AssertionError("second unlock was accepted")
    assert client.state is not None and client.state.username == "alice"
