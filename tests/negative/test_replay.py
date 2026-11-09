"""SR-11: replayed initial messages (last-resort prekeys, where SR-10 alone cannot help)."""

from __future__ import annotations

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.errors import ReplayError
from tests.conftest import NOW


def test_initial_message_replay(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    cache = handshake.ReplayCache()
    msg, _ = handshake.initiate(alice_identity, bob.bundle(with_one_time=False), b"x", now=NOW)
    handshake.respond(bob, msg, replay_cache=cache, now=NOW)
    with pytest.raises(ReplayError):
        handshake.respond(bob, msg, replay_cache=cache, now=NOW)


def test_without_cache_last_resort_replay_would_succeed(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    """Shows *why* the cache exists: last-resort prekeys are reusable by design."""
    msg, _ = handshake.initiate(alice_identity, bob.bundle(with_one_time=False), b"x", now=NOW)
    handshake.respond(bob, msg, now=NOW)
    assert handshake.respond(bob, msg, now=NOW).plaintext == b"x"
