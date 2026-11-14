"""Local web UI server for the PQ-Chat client (M6). Crypto never runs in the browser.

Defences (threat model T-29 to T-31, SR-28, SR-29):

* binds to 127.0.0.1 by default;
* every request must carry an allowed ``Host`` header (DNS-rebinding defence);
* every /api request must carry the per-launch random token in ``X-PQChat-Token`` and, if the
  browser sends an ``Origin``, it must be our own origin (CSRF defence);
* strict Content-Security-Policy: scripts and styles only from this origin, no inline code,
  no framing, no third-party connections; plus nosniff and no-referrer;
* the browser receives text only; the UI inserts it with ``textContent`` (see static/app.js).
"""

from __future__ import annotations

import hmac
import os
import secrets
import ssl
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from pqchat.client.core import ChatClient, KeyChangedError, LockedError
from pqchat.client.relay_client import RelayError
from pqchat.crypto.errors import CryptoError
from pqchat.protocol.errors import ProtocolError
from pqchat.wire import USERNAME_RE

STATIC = Path(__file__).parent / "static"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

NAME = Field(pattern=USERNAME_RE.pattern)


class UnlockBody(BaseModel):
    username: str = NAME
    passphrase: str = Field(min_length=10, max_length=256)


class SendBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class VerifyBody(BaseModel):
    verified: bool


def create_ui(
    client: ChatClient,
    token: str,
    allowed_hosts: set[str],
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"error": "bad host"}, status_code=421, headers=SECURITY_HEADERS)
        if request.url.path.startswith("/api/"):
            origin = request.headers.get("origin")
            if origin is not None and origin not in allowed_origins:
                return JSONResponse({"error": "bad origin"}, 403, headers=SECURITY_HEADERS)
            given = request.headers.get("x-pqchat-token", "")
            if not hmac.compare_digest(given.encode(), token.encode()):
                return JSONResponse({"error": "bad token"}, 401, headers=SECURITY_HEADERS)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def handle_errors(exc: Exception) -> HTTPException:
        if isinstance(exc, KeyChangedError):
            return HTTPException(409, "key_changed")
        if isinstance(exc, LockedError):
            return HTTPException(423, "locked")
        if isinstance(exc, RelayError):
            # Relay answers about the *request* map to client errors; only a broken relay
            # connection is a gateway error (ZAP finding, M8).
            status = {"unknown_user": 404, "no_bundle": 404, "rate_limited": 429}.get(exc.code, 502)
            return HTTPException(status, exc.code)
        if isinstance(exc, CryptoError):
            return HTTPException(401, "wrong username or passphrase")
        if isinstance(exc, ProtocolError):
            return HTTPException(400, "protocol_error")
        return HTTPException(400, "bad_request")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/static/{name}")
    def static(name: str) -> FileResponse:
        files = {"app.js": "text/javascript", "style.css": "text/css"}
        if name not in files:
            raise HTTPException(404)
        return FileResponse(STATIC / name, media_type=files[name])

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        if client.state is None:
            return {"locked": True, "has_keystore": client.exists()}
        return {"locked": False, **client.overview()}

    @app.post("/api/unlock")
    async def unlock(body: UnlockBody) -> dict[str, Any]:
        if client.state is not None:
            # Re-unlocking would reload state and replace the live relay connection, dropping
            # in-flight requests, or swap identities (ZAP finding, M8).
            raise HTTPException(409, "already unlocked")
        try:
            client.unlock(body.username, body.passphrase)
            await client.connect()
        except Exception as exc:
            raise handle_errors(exc) from None
        return client.overview()

    @app.get("/api/chat/{name}")
    def chat(name: str) -> dict[str, Any]:
        if not USERNAME_RE.fullmatch(name):
            raise HTTPException(400, "bad name")
        try:
            return client.chat_view(name)
        except Exception as exc:
            raise handle_errors(exc) from None

    @app.post("/api/chat/{name}/send")
    async def send(name: str, body: SendBody) -> dict[str, Any]:
        if not USERNAME_RE.fullmatch(name):
            raise HTTPException(400, "bad name")
        try:
            await client.send_text(name, body.text)
            return client.chat_view(name)
        except Exception as exc:
            raise handle_errors(exc) from None

    @app.post("/api/chat/{name}/verify")
    def verify(name: str, body: VerifyBody) -> dict[str, Any]:
        try:
            client.set_verified(name, body.verified)
            return client.chat_view(name)
        except Exception as exc:
            raise handle_errors(exc) from None

    @app.post("/api/chat/{name}/accept-key")
    def accept_key(name: str) -> dict[str, Any]:
        try:
            client.accept_new_key(name)
            return client.chat_view(name)
        except Exception as exc:
            raise handle_errors(exc) from None

    return app


def main() -> None:
    import uvicorn

    data_dir = os.environ.get("PQCHAT_DATA_DIR", os.path.expanduser("~/.pqchat"))
    relay = os.environ.get("PQCHAT_RELAY_URL", "ws://127.0.0.1:8000/ws")
    bind = os.environ.get("PQCHAT_UI_BIND", "127.0.0.1")
    port = int(os.environ.get("PQCHAT_UI_PORT", "8701"))
    public_port = int(os.environ.get("PQCHAT_UI_PUBLIC_PORT", str(port)))
    ca = os.environ.get("PQCHAT_RELAY_CA")
    ssl_ctx = None
    if relay.startswith("wss://"):
        from pqchat.client.tls import client_context

        ssl_ctx = client_context(ca)
    token = secrets.token_urlsafe(32)
    hosts = {f"127.0.0.1:{public_port}", f"localhost:{public_port}"}
    app = create_ui(ChatClient(data_dir, relay, ssl_ctx), token, hosts)
    # The token is shown once, on the terminal of the person who started the client.
    print(f"PQ-Chat UI: http://127.0.0.1:{public_port}/#token={token}", flush=True)  # noqa: T201
    uvicorn.run(app, host=bind, port=port, server_header=False, log_level="warning")


__all__ = ["create_ui", "main", "ssl"]
