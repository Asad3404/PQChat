"""Two real clients and a real relay (in-process): M6 end-to-end behaviour."""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from pqchat.client.core import ChatClient, KeyChangedError
from pqchat.crypto.errors import CryptoError
from pqchat.protocol.bundle import IdentityKeys
from tests.relay_harness import running_relay

PASS = "correct horse battery staple"  # noqa: S105 - synthetic test passphrase


async def _wait_for(pred, timeout: float = 10.0) -> None:  # type: ignore[no-untyped-def]
    deadline = asyncio.get_running_loop().time() + timeout
    while not pred():
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError
        await asyncio.sleep(0.02)


def _texts(c: ChatClient, peer: str) -> list[str]:
    assert c.state is not None
    return [m["text"] for m in c.state.history.get(peer, []) if m["dir"] == "in"]


def test_chat_persistence_and_restart(tmp_path: Path) -> None:
    async def scenario(url: str) -> None:
        alice = ChatClient(tmp_path / "alice", url)
        bob = ChatClient(tmp_path / "bob", url)
        alice.unlock("alice", PASS)
        bob.unlock("bob", PASS)
        await alice.connect()
        await bob.connect()

        await alice.send_text("bob", "hi bob")  # initial (handshake) message
        await _wait_for(lambda: _texts(bob, "alice") == ["hi bob"])
        for i in range(5):
            await bob.send_text("alice", f"reply {i}")
        await _wait_for(lambda: len(_texts(alice, "bob")) == 5)
        assert alice.safety_number("bob") == bob.safety_number("alice")

        # restart bob from his encrypted key store; the session must survive
        await bob.close()
        bob2 = ChatClient(tmp_path / "bob", url)
        bob2.unlock("bob", PASS)
        await bob2.connect()
        await alice.send_text("bob", "after restart")
        await _wait_for(lambda: "after restart" in _texts(bob2, "alice"))
        await bob2.send_text("alice", "still here")
        await _wait_for(lambda: "still here" in _texts(alice, "bob"))
        await alice.close()
        await bob2.close()

    with running_relay() as (addr, _):
        asyncio.run(scenario(f"ws://{addr}/ws"))

    ks = tmp_path / "bob" / "keystore.pqks"
    assert stat.S_IMODE(os.stat(ks).st_mode) == 0o600  # SR-26
    raw = ks.read_bytes()
    assert b"hi bob" not in raw and b"reply" not in raw  # SR-27: history only encrypted
    with pytest.raises(CryptoError):
        ChatClient(tmp_path / "bob", "ws://x").unlock("bob", "wrong passphrase!")


def test_identity_change_blocks_sending(tmp_path: Path) -> None:
    """SR-17: if the relay serves a different identity for a pinned contact, sending stops."""

    async def scenario(url: str) -> None:
        alice = ChatClient(tmp_path / "alice", url)
        bob = ChatClient(tmp_path / "bob", url)
        alice.unlock("alice", PASS)
        bob.unlock("bob", PASS)
        await alice.connect()
        await bob.connect()
        assert alice.state is not None
        # Pretend alice pinned a different "bob" earlier (as if the relay swapped keys now).
        from pqchat.client.core import Contact

        alice.state.contacts["bob"] = Contact(IdentityKeys.generate().public.encode())
        with pytest.raises(KeyChangedError):
            await alice.send_text("bob", "hello?")
        assert alice.chat_view("bob")["key_changed"] is True
        with pytest.raises(KeyChangedError):  # still blocked
            await alice.send_text("bob", "hello again?")
        alice.accept_new_key("bob")
        await alice.send_text("bob", "ok now")
        await _wait_for(lambda: _texts(bob, "alice") == ["ok now"])
        await alice.close()
        await bob.close()

    with running_relay() as (addr, _):
        asyncio.run(scenario(f"ws://{addr}/ws"))


def test_forged_messages_are_dropped_not_shown(tmp_path: Path) -> None:
    async def scenario(url: str) -> None:
        alice = ChatClient(tmp_path / "alice", url)
        bob = ChatClient(tmp_path / "bob", url)
        alice.unlock("alice", PASS)
        bob.unlock("bob", PASS)
        await alice.connect()
        await bob.connect()
        await alice.send_text("bob", "real")
        await _wait_for(lambda: _texts(bob, "alice") == ["real"])
        assert alice.relay is not None
        await alice.relay.send("bob", "msg", b"\x01" + os.urandom(200))  # garbage ciphertext
        await alice.relay.send("bob", "init", os.urandom(300))
        assert bob.state is not None
        await _wait_for(lambda: bob.state.dropped == 2)  # type: ignore[union-attr]
        assert _texts(bob, "alice") == ["real"]
        await alice.close()
        await bob.close()

    with running_relay() as (addr, _):
        asyncio.run(scenario(f"ws://{addr}/ws"))


def test_message_length_limits(tmp_path: Path) -> None:
    c = ChatClient(tmp_path / "c", "ws://unused")
    c.unlock("carol", PASS)

    async def scenario() -> None:
        with pytest.raises(ValueError):
            await c.send_text("bob", "")
        with pytest.raises(ValueError):
            await c.send_text("bob", "x" * 4001)

    asyncio.run(scenario())
