"""Async client for the relay's WebSocket API (see pqchat.server.app)."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.asyncio.client import ClientConnection

from pqchat import wire
from pqchat.crypto import labels
from pqchat.protocol.bundle import IdentityKeys, relay_auth_message

RESPONSES = {"ok", "error", "bundle", "prekey_count"}


class RelayError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Delivery:
    id: int
    sender: str
    kind: str
    blob: bytes


class RelayClient:
    def __init__(
        self,
        url: str,
        username: str,
        identity: IdentityKeys,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.url = url
        self.username = username
        self.identity = identity
        self.ssl_context = ssl_context
        self.inbox: asyncio.Queue[Delivery] = asyncio.Queue()
        self._ws: ClientConnection | None = None
        self._pending: dict[int, asyncio.Future[tuple[str, dict[str, Any]]]] = {}
        self._next_req = 1
        self._reader: asyncio.Task[None] | None = None

    async def connect(self, *, register: bool) -> None:
        self._ws = await websockets.connect(
            self.url, ssl=self.ssl_context, max_size=wire.MAX_ENVELOPE, compression=None
        )
        _, f = wire.parse(await self._ws.recv(), {"challenge"})
        purpose = "register" if register else "login"
        sig = self.identity.signing.sign(
            labels.SIG_RELAY_AUTH, relay_auth_message(purpose, self.username, f["nonce"])
        )
        fields: dict[str, Any] = {
            "username": self.username,
            "sig_ed": sig.ed25519,
            "sig_pq": sig.mldsa65,
        }
        if register:
            fields["identity"] = self.identity.public.encode()
        self._reader = asyncio.create_task(self._read_loop())
        try:
            await self._request(purpose, **fields)
        except BaseException:
            await self.close()  # never leave a half-open connection behind
            raise

    async def _read_loop(self) -> None:
        if self._ws is None:
            return
        try:
            async for raw in self._ws:
                try:
                    kind, f = wire.parse(raw, RESPONSES | {"deliver"})
                except wire.EnvelopeError:
                    continue  # never trust the relay: ignore malformed envelopes
                if kind == "deliver":
                    await self.inbox.put(Delivery(f["id"], f["from"], f["kind"], f["blob"]))
                    continue
                if kind == "error" and f["req"] == 0:
                    # Rejected before the relay could read our request id (e.g. rate limit):
                    # fail every outstanding request instead of letting them time out.
                    for pending in self._pending.values():
                        if not pending.done():
                            pending.set_result((kind, f))
                    self._pending.clear()
                    continue
                fut = self._pending.pop(f["req"], None)
                if fut is not None and not fut.done():
                    fut.set_result((kind, f))
        except websockets.ConnectionClosed:
            pass
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(RelayError("connection_closed"))

    async def _request(self, envelope_type: str, /, **fields: Any) -> tuple[str, dict[str, Any]]:
        if self._ws is None:
            raise RelayError("not_connected")
        req = self._next_req
        self._next_req += 1
        fut: asyncio.Future[tuple[str, dict[str, Any]]] = asyncio.get_running_loop().create_future()
        self._pending[req] = fut
        await self._ws.send(wire.build(envelope_type, req=req, **fields))
        kind, f = await asyncio.wait_for(fut, timeout=30)
        if kind == "error":
            raise RelayError(f["code"])
        return kind, f

    async def upload_prekeys(self, signed: list[bytes], one_time: list[bytes]) -> None:
        await self._request("upload_prekeys", signed=signed, one_time=one_time)

    async def fetch_bundle(self, username: str) -> bytes:
        _, f = await self._request("fetch_bundle", username=username)
        return bytes(f["bundle"])

    async def send(self, to: str, kind: str, blob: bytes) -> None:
        await self._request("send", to=to, kind=kind, blob=blob)

    async def ack(self, message_id: int) -> None:
        if self._ws is not None:
            await self._ws.send(wire.build("ack", id=message_id))

    async def count_prekeys(self) -> int:
        _, f = await self._request("count_prekeys")
        return int(f["one_time"])

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
        if self._reader is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader
