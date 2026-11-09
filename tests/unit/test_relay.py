"""Relay behaviour against a real server (M6): SR-10, SR-19, SR-20, SR-21, SR-9."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
import websockets

from pqchat import wire
from pqchat.client.relay_client import RelayClient, RelayError
from pqchat.protocol.bundle import IdentityKeys, PrekeyBundle, PrekeyStore
from pqchat.protocol.modes import Mode, Policy
from pqchat.server.storage import Storage
from tests.relay_harness import running_relay


def run(coro):  # type: ignore[no-untyped-def]
    return asyncio.run(coro)


def _store(n: int = 3) -> PrekeyStore:
    s = PrekeyStore(IdentityKeys.generate())
    s.rotate_signed(int(time.time()))
    s.add_one_time(n, int(time.time()))
    return s


async def _client(addr: str, name: str, store: PrekeyStore, register: bool = True) -> RelayClient:
    c = RelayClient(f"ws://{addr}/ws", name, store.identity)
    await c.connect(register=register)
    return c


async def _upload(c: RelayClient, store: PrekeyStore) -> None:
    spk, pqspk = store.current_signed()
    ot = [pk.encode() for _, pk in store.one_time_dh.values()]
    ot += [pk.encode() for _, pk in store.one_time_kem.values()]
    await c.upload_prekeys([spk.encode(), pqspk.encode()], ot)


def test_register_upload_fetch_and_one_time_prekeys_used_once() -> None:
    async def scenario(addr: str) -> None:
        bob_store = _store(2)
        bob = await _client(addr, "bob", bob_store)
        await _upload(bob, bob_store)
        assert await bob.count_prekeys() == 2
        alice = await _client(addr, "alice", _store())
        opk_ids = []
        for _ in range(3):
            b = PrekeyBundle.decode(await alice.fetch_bundle("bob"))
            b.verify(Mode.HYBRID, int(time.time()), Policy())
            opk_ids.append(b.opk.key_id if b.opk else None)
        assert opk_ids[0] != opk_ids[1] and None not in opk_ids[:2]
        assert opk_ids[2] is None  # exhausted: last-resort prekeys only
        assert await bob.count_prekeys() == 0
        await alice.close()
        await bob.close()

    with running_relay() as (addr, _):
        run(scenario(addr))


def test_send_deliver_ack_and_offline_queue() -> None:
    async def scenario(addr: str, storage: Storage) -> None:
        alice_store, bob_store = _store(), _store()
        alice = await _client(addr, "alice", alice_store)
        bob = await _client(addr, "bob", bob_store)
        await bob.close()  # bob goes offline
        await alice.send("bob", "msg", b"\x01ciphertext")
        assert len(storage.pending("bob", int(time.time()))) == 1
        bob = await _client(addr, "bob", bob_store, register=False)
        d = await asyncio.wait_for(bob.inbox.get(), 5)
        assert (d.sender, d.kind, d.blob) == ("alice", "msg", b"\x01ciphertext")
        await alice.ack(d.id)  # someone else cannot delete bob's message
        await asyncio.sleep(0.1)
        assert len(storage.pending("bob", int(time.time()))) == 1
        await bob.ack(d.id)
        await asyncio.sleep(0.1)
        assert storage.pending("bob", int(time.time())) == []  # SR-20 deleted on delivery
        # live delivery
        await alice.send("bob", "msg", b"live")
        assert (await asyncio.wait_for(bob.inbox.get(), 5)).blob == b"live"
        with pytest.raises(RelayError, match="unknown_user"):
            await alice.send("nobody", "msg", b"x")
        await alice.close()
        await bob.close()

    with running_relay() as (addr, storage):
        run(scenario(addr, storage))


def test_name_is_bound_to_first_identity() -> None:
    async def scenario(addr: str) -> None:
        c = await _client(addr, "alice", _store())
        await c.close()
        with pytest.raises(RelayError, match="auth_failed"):
            await _client(addr, "alice", _store())  # squatting with another identity
        with pytest.raises(RelayError, match="auth_failed"):
            await _client(addr, "alice", _store(), register=False)  # login with wrong keys

    with running_relay() as (addr, _):
        run(scenario(addr))


def test_auth_signature_cannot_be_replayed() -> None:
    """A captured login signature is bound to that connection's nonce."""

    async def scenario(addr: str) -> None:
        store = _store()
        first = await _client(addr, "alice", store)
        await first.close()
        from pqchat.crypto import labels
        from pqchat.protocol.bundle import relay_auth_message

        old_sig = store.identity.signing.sign(
            labels.SIG_RELAY_AUTH, relay_auth_message("login", "alice", b"\x00" * 32)
        )
        async with websockets.connect(f"ws://{addr}/ws") as ws:
            await ws.recv()  # fresh challenge, different from the zero nonce
            await ws.send(
                wire.build(
                    "login", req=1, username="alice", sig_ed=old_sig.ed25519, sig_pq=old_sig.mldsa65
                )
            )
            _, f = wire.parse(await ws.recv(), {"error"})
            assert f["code"] == "auth_failed"

    with running_relay() as (addr, _):
        run(scenario(addr))


def test_relay_rejects_bad_prekeys() -> None:
    async def scenario(addr: str) -> None:
        store = _store()
        c = await _client(addr, "alice", store)
        spk, pqspk = store.current_signed()
        bad = bytearray(spk.encode())
        bad[-1] ^= 1
        with pytest.raises(RelayError, match="bad_prekey"):
            await c.upload_prekeys([bytes(bad), pqspk.encode()], [])
        foreign = _store().current_signed()[0]  # signed by someone else
        with pytest.raises(RelayError, match="bad_prekey"):
            await c.upload_prekeys([foreign.encode()], [])
        with pytest.raises(RelayError, match="no_bundle"):
            await c.fetch_bundle("alice")  # nothing valid uploaded
        await c.close()

    with running_relay() as (addr, _):
        run(scenario(addr))


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[1,2]",
        json.dumps({"type": "nope"}),
        json.dumps({"type": "login", "req": 1, "username": "alice"}),  # missing fields
        json.dumps({"type": "login", "req": 1, "username": "A!", "sig_ed": "", "sig_pq": ""}),
        json.dumps(
            {"type": "send", "req": 1, "to": "bob", "kind": "msg", "blob": "AA"}
        ),  # pre-auth
    ],
)
def test_malformed_envelopes_are_rejected(payload: str) -> None:
    async def scenario(addr: str) -> None:
        async with websockets.connect(f"ws://{addr}/ws") as ws:
            await ws.recv()
            await ws.send(payload)
            _, f = wire.parse(await ws.recv(), {"error"})
            assert f["code"] == "bad_request"

    with running_relay() as (addr, _):
        run(scenario(addr))


def test_repeated_garbage_closes_connection() -> None:
    async def scenario(addr: str) -> None:
        async with websockets.connect(f"ws://{addr}/ws") as ws:
            await ws.recv()
            for _ in range(5):
                await ws.send("garbage")
                await ws.recv()
            with pytest.raises(websockets.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 5)

    with running_relay() as (addr, _):
        run(scenario(addr))


def test_oversized_frame_is_refused() -> None:
    async def scenario(addr: str) -> None:
        async with websockets.connect(f"ws://{addr}/ws", max_size=None) as ws:
            await ws.recv()
            await ws.send("x" * (wire.MAX_ENVELOPE + 10))
            with pytest.raises(websockets.ConnectionClosed):
                await asyncio.wait_for(ws.recv(), 5)

    with running_relay(ws_max_size=wire.MAX_ENVELOPE) as (addr, _):
        run(scenario(addr))


def test_retention_purge() -> None:
    s = Storage()
    s.create_account("bob", b"id", 0)
    s.enqueue("bob", "alice", "msg", b"x", now=0)
    assert s.purge_expired(now=31 * 86400) == 1
    assert s.pending("bob", 31 * 86400) == []
