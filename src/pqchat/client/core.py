"""The PQ-Chat client: key store, contacts, sessions and the relay connection.

Security behaviour implemented here:

* SR-26/SR-27: everything secret (keys, sessions, history) lives in one encrypted key-store file,
  written atomically with mode 0600.
* SR-17: a contact's identity is pinned on first use (TOFU). If a later bundle or initial message
  carries a different identity, sending to that contact is blocked until the user accepts the new
  safety number.
* SR-22: one-time prekeys are replenished when the relay reports fewer than ``LOW_WATER``.
* Every received message is decrypted before it is acknowledged; anything that fails verification
  is dropped and counted, never shown.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pqchat.client import serialize
from pqchat.client.relay_client import Delivery, RelayClient, RelayError
from pqchat.crypto.errors import CryptoError
from pqchat.crypto.keystore_crypto import decrypt_keystore, encrypt_keystore
from pqchat.logsafe import get_logger
from pqchat.protocol.bundle import IdentityKeys, IdentityPublic, PrekeyBundle, PrekeyStore
from pqchat.protocol.errors import ProtocolError
from pqchat.protocol.handshake import ReplayCache
from pqchat.protocol.modes import Policy
from pqchat.protocol.safety import format_groups, safety_number
from pqchat.protocol.session import Session
from pqchat.wire import b64e

log = get_logger("pqchat.client")

ONE_TIME_BATCH = 50
UPLOAD_BATCH = 25
LOW_WATER = 20
SIGNED_ROTATE_BEFORE = 2 * 86_400
MAX_TEXT = 4000


class KeyChangedError(Exception):
    """The contact's identity key changed; the user must re-verify before sending (SR-17)."""


class LockedError(Exception):
    pass


@dataclass
class Contact:
    identity: bytes  # pinned IdentityPublic encoding
    verified: bool = False
    pending_identity: bytes | None = None  # a *different* identity we have seen

    @property
    def key_changed(self) -> bool:
        return self.pending_identity is not None


@dataclass
class ClientState:
    username: str
    identity: IdentityKeys
    prekeys: PrekeyStore
    registered: bool = False
    replay: ReplayCache = field(default_factory=ReplayCache)
    contacts: dict[str, Contact] = field(default_factory=dict)
    sessions: dict[str, Session] = field(default_factory=dict)
    history: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    dropped: int = 0


class ChatClient:
    def __init__(
        self, data_dir: str | Path, relay_url: str, ssl_context: ssl.SSLContext | None = None
    ) -> None:
        self.data_dir = Path(data_dir)
        self.relay_url = relay_url
        self.ssl_context = ssl_context
        self.state: ClientState | None = None
        self._passphrase: str | None = None
        self.relay: RelayClient | None = None
        self.connected = False
        self.version = 0  # bumped on every change; the UI polls it
        self._task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ key store
    @property
    def path(self) -> Path:
        return self.data_dir / "keystore.pqks"

    def exists(self) -> bool:
        return self.path.exists()

    def unlock(self, username: str, passphrase: str) -> None:
        if self.path.exists():
            doc = json.loads(decrypt_keystore(passphrase, self.path.read_bytes()))
            if doc["username"] != username:
                raise CryptoError("wrong username or passphrase")
            self.state = self._load(doc)
        else:
            now = int(time.time())
            ident = IdentityKeys.generate()
            store = PrekeyStore(ident)
            store.rotate_signed(now)
            store.add_one_time(ONE_TIME_BATCH, now)
            self.state = ClientState(username, ident, store)
        self._passphrase = passphrase
        self.save()

    def _load(self, d: dict[str, Any]) -> ClientState:
        ident = serialize.identity_from(d["identity"])
        st = ClientState(
            username=d["username"],
            identity=ident,
            prekeys=serialize.prekeys_from(ident, d["prekeys"]),
            registered=bool(d["registered"]),
            replay=serialize.replay_from(d["replay"]),
            dropped=int(d.get("dropped", 0)),
        )
        for name, c in d["contacts"].items():
            st.contacts[name] = Contact(
                serialize._b(c["identity"]),
                bool(c["verified"]),
                serialize._opt_from(c["pending_identity"]),
            )
        for name, s in d["sessions"].items():
            st.sessions[name] = serialize.session_from(ident.public, s)
        st.history = d["history"]
        return st

    def save(self) -> None:
        st = self._require()
        doc = {
            "version": 1,
            "username": st.username,
            "identity": serialize.identity_to(st.identity),
            "prekeys": serialize.prekeys_to(st.prekeys),
            "registered": st.registered,
            "replay": serialize.replay_to(st.replay),
            "contacts": {
                n: {
                    "identity": b64e(c.identity),
                    "verified": c.verified,
                    "pending_identity": serialize._opt(c.pending_identity),
                }
                for n, c in st.contacts.items()
            },
            "sessions": {n: serialize.session_to(s) for n, s in st.sessions.items()},
            "history": st.history,
            "dropped": st.dropped,
        }
        if self._passphrase is None:
            raise LockedError("key store is locked")
        blob = encrypt_keystore(self._passphrase, json.dumps(doc).encode())
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)  # atomic: never a half-written key store
        self.version += 1

    def _require(self) -> ClientState:
        if self.state is None:
            raise LockedError("key store is locked")
        return self.state

    # ------------------------------------------------------------------ relay
    async def connect(self) -> None:
        st = self._require()
        self.relay = RelayClient(self.relay_url, st.username, st.identity, self.ssl_context)
        await self.relay.connect(register=not st.registered)
        if not st.registered:
            st.registered = True
            await self._upload_all()
        await self._maintain_prekeys()
        self.connected = True
        self.version += 1
        self.save()
        self._task = asyncio.create_task(self._receive_loop())

    async def _upload_all(self) -> None:
        st = self._require()
        if self.relay is None:
            raise RelayError("not_connected")
        spk, pqspk = st.prekeys.current_signed()
        ot = [pk.encode() for _, pk in st.prekeys.one_time_dh.values()]
        ot += [pk.encode() for _, pk in st.prekeys.one_time_kem.values()]
        await self._upload_batched([spk.encode(), pqspk.encode()], ot)

    async def _upload_batched(self, signed: list[bytes], one_time: list[bytes]) -> None:
        """The relay accepts at most 25 one-time prekeys per envelope (size limit)."""
        if self.relay is None:
            raise RelayError("not_connected")
        for i in range(0, max(len(one_time), 1), UPLOAD_BATCH):
            await self.relay.upload_prekeys(signed, one_time[i : i + UPLOAD_BATCH])

    async def _maintain_prekeys(self) -> None:
        """Rotate the signed prekeys before they expire; top up one-time prekeys (SR-22)."""
        st = self._require()
        if self.relay is None:
            raise RelayError("not_connected")
        now = int(time.time())
        spk, _ = st.prekeys.current_signed()
        if spk.expires_at - now < SIGNED_ROTATE_BEFORE:
            st.prekeys.rotate_signed(now)
            spk, pqspk = st.prekeys.current_signed()
            await self.relay.upload_prekeys([spk.encode(), pqspk.encode()], [])
        if await self.relay.count_prekeys() < LOW_WATER:
            before_dh, before_kem = set(st.prekeys.one_time_dh), set(st.prekeys.one_time_kem)
            st.prekeys.add_one_time(ONE_TIME_BATCH, now)
            new = [
                pk.encode() for k, (_, pk) in st.prekeys.one_time_dh.items() if k not in before_dh
            ]
            new += [
                pk.encode() for k, (_, pk) in st.prekeys.one_time_kem.items() if k not in before_kem
            ]
            spk, pqspk = st.prekeys.current_signed()
            await self._upload_batched([spk.encode(), pqspk.encode()], new)
        st.prekeys.drop_expired(now)

    async def _receive_loop(self) -> None:
        if self.relay is None:
            raise RelayError("not_connected")
        try:
            while True:
                delivery = await self.relay.inbox.get()
                await self.handle_delivery(delivery)
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self.relay is not None:
            await self.relay.close()
        self.connected = False

    # ------------------------------------------------------------------ contacts / TOFU
    def _pin(self, name: str, identity: IdentityPublic) -> None:
        st = self._require()
        enc = identity.encode()
        contact = st.contacts.get(name)
        if contact is None:
            st.contacts[name] = Contact(enc)  # trust on first use
        elif contact.identity != enc:
            contact.pending_identity = enc
            contact.verified = False
            raise KeyChangedError(name)

    def accept_new_key(self, name: str) -> None:
        st = self._require()
        c = st.contacts[name]
        if c.pending_identity is not None:
            c.identity, c.pending_identity = c.pending_identity, None
            st.sessions.pop(name, None)  # start a fresh session with the new key
            self._log_system(name, "You accepted the new safety number.")
        self.save()

    def set_verified(self, name: str, verified: bool) -> None:
        st = self._require()
        st.contacts[name].verified = verified
        self.save()

    def safety_number(self, name: str) -> list[str] | None:
        st = self._require()
        c = st.contacts.get(name)
        if c is None:
            return None
        peer = IdentityPublic.decode(c.pending_identity or c.identity)
        return format_groups(safety_number(st.identity.public, peer))

    # ------------------------------------------------------------------ messages
    def _log(self, name: str, direction: str, text: str) -> None:
        self._require().history.setdefault(name, []).append(
            {"dir": direction, "text": text, "ts": int(time.time())}
        )

    def _log_system(self, name: str, text: str) -> None:
        self._log(name, "sys", text)

    async def send_text(self, name: str, text: str) -> None:
        st = self._require()
        if not text or len(text) > MAX_TEXT:
            raise ValueError("message must be 1 to 4000 characters")
        if self.relay is None:
            raise RelayError("not_connected")
        contact = st.contacts.get(name)
        if contact is not None and contact.key_changed:
            raise KeyChangedError(name)
        payload = text.encode("utf-8")
        session = st.sessions.get(name)
        if session is None:
            bundle = PrekeyBundle.decode(await self.relay.fetch_bundle(name))
            self._pin(name, bundle.identity)  # raises KeyChangedError on mismatch
            session, wire_msg = Session.initiate(st.identity, bundle, payload, policy=Policy())
            kind = "init"
        else:
            wire_msg, kind = session.encrypt(payload), "msg"
        st.sessions[name] = session
        self._log(name, "out", text)
        self.save()
        await self.relay.send(name, kind, wire_msg)

    async def handle_delivery(self, d: Delivery) -> None:
        st = self._require()
        try:
            if d.kind == "init":
                session, plaintext = Session.accept(st.prekeys, d.blob, replay_cache=st.replay)
                try:
                    self._pin(d.sender, session.peer)
                except KeyChangedError:
                    self._log_system(d.sender, "Safety number changed. Sending is paused.")
                    raise
                st.sessions[d.sender] = session
            else:
                existing = st.sessions.get(d.sender)
                if existing is None:
                    raise ProtocolError("no session")
                plaintext = existing.decrypt(d.blob)
            self._log(d.sender, "in", plaintext.decode("utf-8", errors="replace"))
        except (ProtocolError, KeyChangedError, CryptoError):
            st.dropped += 1
            log.info("dropped an undecryptable or untrusted message")
        self.save()
        if self.relay is not None:
            await self.relay.ack(d.id)
            if d.kind == "init":
                with contextlib.suppress(RelayError):
                    await self._maintain_prekeys()

    # ------------------------------------------------------------------ views for the UI
    def overview(self) -> dict[str, Any]:
        st = self._require()
        names = sorted(set(st.contacts) | set(st.history))
        chats = []
        for n in names:
            msgs = [m for m in st.history.get(n, []) if m["dir"] != "sys"]
            c = st.contacts.get(n)
            chats.append(
                {
                    "name": n,
                    "last": msgs[-1]["text"] if msgs else "",
                    "ts": msgs[-1]["ts"] if msgs else 0,
                    "verified": bool(c and c.verified),
                    "key_changed": bool(c and c.key_changed),
                    "has_session": n in st.sessions,
                }
            )
        chats.sort(key=lambda c: -int(c["ts"]))
        return {
            "username": st.username,
            "connected": self.connected,
            "version": self.version,
            "one_time_prekeys": len(st.prekeys.one_time_dh),
            "chats": chats,
        }

    def chat_view(self, name: str) -> dict[str, Any]:
        st = self._require()
        s = st.sessions.get(name)
        c = st.contacts.get(name)
        session_info = None
        if s is not None:
            k = s.ratchet.state.kem
            session_info = {
                "mode": s.mode.name.lower(),
                "missing": s.missing_messages,
                "pq_interval": k.interval,
                "chains_until_pq": max(0, k.interval // 2 - k.chains_since),
            }
        return {
            "name": name,
            "messages": st.history.get(name, []),
            "verified": bool(c and c.verified),
            "key_changed": bool(c and c.key_changed),
            "safety_number": self.safety_number(name),
            "session": session_info,
        }
