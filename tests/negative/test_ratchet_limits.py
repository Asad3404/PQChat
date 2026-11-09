"""SR-12: skipped-message-key limit and ratchet replays."""

from __future__ import annotations

import pytest

from pqchat.protocol import ratchet
from pqchat.protocol.errors import ProtocolError, ReplayError, VerificationError
from tests.conftest import make_pair


def test_ratchet_replay() -> None:
    alice, bob = make_pair()
    m = alice.encrypt(b"once")
    assert bob.decrypt(m) == b"once"
    with pytest.raises(ReplayError):
        bob.decrypt(m)


def test_replay_of_out_of_order_message() -> None:
    alice, bob = make_pair()
    m0, m1 = alice.encrypt(b"0"), alice.encrypt(b"1")
    bob.decrypt(m1)
    bob.decrypt(m0)  # from the skipped-key store
    with pytest.raises(ReplayError):
        bob.decrypt(m0)


def test_replay_from_an_old_chain() -> None:
    alice, bob = make_pair()
    old = alice.encrypt(b"old")
    bob.decrypt(old)
    alice.decrypt(bob.encrypt(b"reply"))
    bob.decrypt(alice.encrypt(b"new chain"))
    with pytest.raises(ProtocolError):
        bob.decrypt(old)


def test_too_many_skipped_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ratchet, "MAX_SKIP", 5)
    alice, bob = make_pair()
    msgs = [alice.encrypt(b"x") for _ in range(7)]
    with pytest.raises(VerificationError):
        bob.decrypt(msgs[6])  # would need 6 skipped keys
    assert bob.decrypt(msgs[4]) == b"x"  # 4 skipped: allowed, and state was not damaged
