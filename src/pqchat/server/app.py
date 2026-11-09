"""PQ-Chat relay: untrusted store-and-forward server (CLAUDE.md §4 A2, M6).

One WebSocket endpoint, ``/ws``, carrying JSON envelopes (``pqchat.wire``):

1. The relay sends ``challenge`` (32 random bytes).
2. The client sends ``register`` (new name + IdentityPublic) or ``login``, signed with BOTH identity
   keys over ``relay_auth_message(purpose, username, nonce)``. A name is bound to the identity that
   first registered it.
3. Authenticated clients can ``upload_prekeys``, ``fetch_bundle``, ``send``, ``ack`` and
   ``count_prekeys``. Queued messages are pushed as ``deliver``.

The relay never sees plaintext or private keys; it re-verifies uploaded prekeys so it cannot be used
to distribute junk, but clients never trust it and verify everything themselves.

Hardening: no API docs, no Server header, strict envelope parsing, size limits on every field and
on the WebSocket frame, per-connection rate limits (M7), minimal logging (SR-25).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from pqchat import PROTOCOL_VERSION, __version__, wire
from pqchat.crypto import labels
from pqchat.crypto.sig import HybridSignature, verify_hybrid
from pqchat.logsafe import get_logger
from pqchat.protocol.bundle import (
    IdentityPublic,
    PrekeyBundle,
    PrekeyKind,
    decode_prekey,
    relay_auth_message,
)
from pqchat.protocol.encoding import ALG_MLKEM768, ALG_X25519
from pqchat.protocol.errors import ProtocolError
from pqchat.protocol.modes import Mode, Policy
from pqchat.server.ratelimit import RateLimiter
from pqchat.server.storage import Storage

log = get_logger("pqchat.relay")

PRE_AUTH = {"register", "login"}
POST_AUTH = {"upload_prekeys", "fetch_bundle", "send", "ack", "count_prekeys"}
MAX_BAD_ENVELOPES = 5


class Relay:
    def __init__(self, storage: Storage, limiter: RateLimiter | None = None) -> None:
        self.storage = storage
        self.limiter = limiter or RateLimiter()
        # T-16 prekey exhaustion: every account's bundle has its own budget, whoever asks.
        self.target_limiter = RateLimiter(rate=0.2, burst=20, bundle_cost=1)
        self.online: dict[str, WebSocket] = {}

    @staticmethod
    def now() -> int:
        return int(time.time())

    # ------------------------------------------------------------------ authentication
    def _check_auth(
        self,
        purpose: str,
        username: str,
        identity: IdentityPublic,
        fields: dict[str, Any],
        nonce: bytes,
    ) -> bool:
        sig = HybridSignature(fields["sig_ed"], fields["sig_pq"])
        msg = relay_auth_message(purpose, username, nonce)
        return verify_hybrid(identity.sign, sig, labels.SIG_RELAY_AUTH, msg)

    def register(self, fields: dict[str, Any], nonce: bytes) -> str | None:
        try:
            identity = IdentityPublic.decode(fields["identity"])
            identity.verify(Mode.HYBRID)
        except ProtocolError:
            return None
        if not self._check_auth("register", fields["username"], identity, fields, nonce):
            return None
        if not self.storage.create_account(fields["username"], identity.encode(), self.now()):
            return None
        return str(fields["username"])

    def login(self, fields: dict[str, Any], nonce: bytes) -> str | None:
        stored = self.storage.get_identity(fields["username"])
        if stored is None:
            return None
        identity = IdentityPublic.decode(stored)
        if not self._check_auth("login", fields["username"], identity, fields, nonce):
            return None
        return str(fields["username"])

    # ------------------------------------------------------------------ prekeys
    def upload_prekeys(self, user: str, fields: dict[str, Any]) -> str | None:
        identity = IdentityPublic.decode(self.storage.get_identity(user) or b"")
        now = self.now()
        policy = Policy()
        try:
            prekeys = [decode_prekey(b) for b in fields["signed"] + fields["one_time"]]
            for pk in prekeys:
                pk.verify(identity, Mode.HYBRID, now, policy)
        except ProtocolError:
            return "bad_prekey"
        for pk, blob in zip(prekeys, fields["signed"] + fields["one_time"], strict=True):
            if pk.kind is PrekeyKind.SIGNED:
                self.storage.put_signed_prekey(
                    user, pk.alg, pk.key_id, pk.created_at, pk.expires_at, blob
                )
            elif not self.storage.add_one_time(user, pk.alg, pk.key_id, pk.expires_at, blob):
                return "too_many_prekeys"
        return None

    def fetch_bundle(self, username: str) -> bytes | None:
        stored = self.storage.get_identity(username)
        now = self.now()
        if stored is None:
            return None
        spk = self.storage.newest_signed_prekey(username, ALG_X25519, now)
        pqspk = self.storage.newest_signed_prekey(username, ALG_MLKEM768, now)
        if spk is None or pqspk is None:
            return None
        opk = self.storage.take_one_time(username, ALG_X25519, now)
        pqopk = self.storage.take_one_time(username, ALG_MLKEM768, now)
        bundle = PrekeyBundle(
            identity=IdentityPublic.decode(stored),
            spk=decode_prekey(spk),
            pqspk=decode_prekey(pqspk),
            opk=decode_prekey(opk) if opk else None,
            pqopk=decode_prekey(pqopk) if pqopk else None,
        )
        return bundle.encode()

    # ------------------------------------------------------------------ connection
    async def deliver_pending(self, user: str, ws: WebSocket) -> None:
        for m in self.storage.pending(user, self.now()):
            await ws.send_text(
                wire.build("deliver", id=m.id, kind=m.kind, blob=m.blob, **{"from": m.sender})
            )

    async def handle(self, ws: WebSocket) -> None:
        await ws.accept()
        nonce = os.urandom(32)
        await ws.send_text(wire.build("challenge", nonce=nonce))
        user: str | None = None
        bad = 0
        conn_key = f"conn:{id(ws)}"
        try:
            while True:
                raw = await ws.receive_text()
                if not self.limiter.allow(conn_key):
                    await ws.close(code=1008)  # policy violation: rate limit
                    return
                try:
                    kind, f = wire.parse(raw, POST_AUTH if user else PRE_AUTH)
                except wire.EnvelopeError:
                    bad += 1
                    await ws.send_text(wire.build("error", req=0, code="bad_request"))
                    if bad >= MAX_BAD_ENVELOPES:
                        await ws.close(code=1008)
                        return
                    continue
                req = int(f.get("req", 0))
                if user is None:
                    user = self.register(f, nonce) if kind == "register" else self.login(f, nonce)
                    if user is None:
                        await ws.send_text(wire.build("error", req=req, code="auth_failed"))
                        await ws.close(code=1008)
                        return
                    nonce = b""  # a challenge is single-use
                    old = self.online.get(user)
                    self.online[user] = ws
                    if old is not None:
                        with contextlib.suppress(Exception):
                            await old.close(code=1000)
                    await ws.send_text(wire.build("ok", req=req))
                    log.info("client authenticated")
                    await self.deliver_pending(user, ws)
                    continue
                await self.dispatch(user, ws, kind, f, req)
        except WebSocketDisconnect:
            pass
        finally:
            if user is not None and self.online.get(user) is ws:
                del self.online[user]

    async def dispatch(
        self, user: str, ws: WebSocket, kind: str, f: dict[str, Any], req: int
    ) -> None:
        if kind == "upload_prekeys":
            err = self.upload_prekeys(user, f)
            await ws.send_text(
                wire.build("error", req=req, code=err) if err else wire.build("ok", req=req)
            )
        elif kind == "fetch_bundle":
            if not self.limiter.allow(
                f"bundle:{user}:{f['username']}", cost=self.limiter.bundle_cost
            ):
                await ws.send_text(wire.build("error", req=req, code="rate_limited"))
                return
            bundle = self.fetch_bundle(f["username"])
            if bundle is None:
                await ws.send_text(wire.build("error", req=req, code="no_bundle"))
            else:
                await ws.send_text(
                    wire.build("bundle", req=req, username=f["username"], bundle=bundle)
                )
        elif kind == "send":
            if self.storage.get_identity(f["to"]) is None:
                await ws.send_text(wire.build("error", req=req, code="unknown_user"))
                return
            msg_id = self.storage.enqueue(f["to"], user, f["kind"], f["blob"], self.now())
            await ws.send_text(wire.build("ok", req=req))
            peer = self.online.get(f["to"])
            if peer is not None:
                with contextlib.suppress(Exception):
                    await peer.send_text(
                        wire.build(
                            "deliver", id=msg_id, kind=f["kind"], blob=f["blob"], **{"from": user}
                        )
                    )
        elif kind == "ack":
            self.storage.ack(user, f["id"])
        elif kind == "count_prekeys":
            n = min(
                self.storage.count_one_time(user, ALG_X25519),
                self.storage.count_one_time(user, ALG_MLKEM768),
            )
            await ws.send_text(wire.build("prekey_count", req=req, one_time=n))


def create_app(storage: Storage | None = None, limiter: RateLimiter | None = None) -> FastAPI:
    relay = Relay(storage or Storage(os.environ.get("PQCHAT_RELAY_DB", ":memory:")), limiter)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async def purge() -> None:  # SR-20: expire old messages and prekeys hourly
            while True:
                relay.storage.purge_expired(relay.now())
                await asyncio.sleep(3600)

        task = asyncio.create_task(purge())
        yield
        task.cancel()

    app = FastAPI(
        title="PQ-Chat relay",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.relay = relay

    @app.get("/healthz")
    def healthz() -> dict[str, object]:
        """Liveness probe. Returns no user data."""
        return {"status": "ok", "service": "pqchat-relay", "protocol_version": PROTOCOL_VERSION}

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await relay.handle(ws)

    return app


app = create_app()


def main() -> None:
    host = os.environ.get("PQCHAT_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("PQCHAT_RELAY_PORT", "8000"))
    from pqchat.server.tls import serve

    serve(
        "pqchat.server.app:app",
        host=host,
        port=port,
        certfile=os.environ.get("PQCHAT_TLS_CERT"),
        keyfile=os.environ.get("PQCHAT_TLS_KEY"),
        ws_max_size=wire.MAX_ENVELOPE,
    )


if __name__ == "__main__":
    main()
