"""SR-34 / SR-6: default policy is hybrid only."""

from __future__ import annotations

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.errors import DowngradeError
from pqchat.protocol.modes import Mode, Policy
from tests.conftest import NOW


def test_default_policy() -> None:
    p = Policy()
    assert p.allowed(Mode.HYBRID)
    assert not p.allowed(Mode.CLASSICAL)
    assert not p.allowed(Mode.PQ_ONLY)


@pytest.mark.parametrize("mode", [Mode.CLASSICAL, Mode.PQ_ONLY])
def test_initiator_refuses_non_default_modes(
    alice_identity: IdentityKeys, bob: PrekeyStore, mode: Mode
) -> None:
    with pytest.raises(DowngradeError):
        handshake.initiate(alice_identity, bob.bundle(), b"x", mode=mode, now=NOW)


@pytest.mark.parametrize("mode", [Mode.CLASSICAL, Mode.PQ_ONLY])
def test_responder_refuses_non_default_modes(
    alice_identity: IdentityKeys, bob: PrekeyStore, mode: Mode
) -> None:
    lenient = Policy(allow_classical=True, allow_pq_only=True)
    msg, _ = handshake.initiate(
        alice_identity, bob.bundle(), b"x", mode=mode, policy=lenient, now=NOW
    )
    with pytest.raises(DowngradeError):
        handshake.respond(bob, msg, now=NOW)
