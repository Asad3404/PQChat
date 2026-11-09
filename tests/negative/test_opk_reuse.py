"""SR-10: a one-time prekey works once."""

from __future__ import annotations

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.errors import ReplayError
from tests.conftest import NOW


def test_same_message_twice(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    msg, _ = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)
    handshake.respond(bob, msg, now=NOW)
    with pytest.raises(ReplayError):
        handshake.respond(bob, msg, now=NOW)


def test_two_initiators_get_same_one_time_prekey(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    """A malicious relay hands the same one-time prekey to two people."""
    bundle = bob.bundle()
    first, _ = handshake.initiate(alice_identity, bundle, b"a", now=NOW)
    second, _ = handshake.initiate(IdentityKeys.generate(), bundle, b"c", now=NOW)
    handshake.respond(bob, first, now=NOW)
    with pytest.raises(ReplayError):
        handshake.respond(bob, second, now=NOW)
