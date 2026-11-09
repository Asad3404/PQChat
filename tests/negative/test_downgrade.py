"""SR-6: downgrade attempts by a network attacker or malicious relay (T-04)."""

from __future__ import annotations

import dataclasses

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, PrekeyStore
from pqchat.protocol.errors import DowngradeError, ProtocolError
from pqchat.protocol.modes import Mode, Policy
from tests.conftest import NOW


def test_relay_strips_pq_prekeys(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    stripped = dataclasses.replace(bob.bundle(), pqspk=None, pqopk=None)
    with pytest.raises(DowngradeError):
        handshake.initiate(alice_identity, stripped, b"x", now=NOW)


def test_mode_byte_rewritten_to_classical(alice_identity: IdentityKeys, bob: PrekeyStore) -> None:
    msg, _ = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)
    tampered = msg[:1] + bytes([Mode.CLASSICAL]) + msg[2:]
    lenient = Policy(allow_classical=True)
    with pytest.raises(DowngradeError):  # suite bytes no longer match the mode
        handshake.respond(bob, tampered, policy=lenient, now=NOW)


def test_mode_and_suite_rewritten_consistently(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    """Even a consistent rewrite fails: the structure and the AEAD AD no longer match."""
    msg, _ = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)
    tampered = msg[:1] + bytes([Mode.CLASSICAL, 1, 1, 1]) + msg[5:]
    with pytest.raises(ProtocolError):
        handshake.respond(bob, tampered, policy=Policy(allow_classical=True), now=NOW)


def test_hybrid_client_refuses_classical_session_by_default(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    msg, _ = handshake.initiate(
        alice_identity,
        bob.bundle(),
        b"x",
        mode=Mode.CLASSICAL,
        policy=Policy(allow_classical=True),
        now=NOW,
    )
    with pytest.raises(DowngradeError):
        handshake.respond(bob, msg, now=NOW)
