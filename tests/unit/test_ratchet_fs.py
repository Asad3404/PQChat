"""SR-13 forward secrecy: a state stolen now does not decrypt earlier messages."""

from __future__ import annotations

import pytest

from pqchat.protocol.errors import ProtocolError
from pqchat.protocol.padding import unpad
from pqchat.protocol.ratchet import Ratchet
from tests.conftest import make_pair


def test_stolen_state_cannot_decrypt_past_messages() -> None:
    alice, bob = make_pair()
    past = [alice.encrypt(f"past {i}".encode()) for i in range(3)]
    for m in past:
        bob.decrypt(m)
    alice.decrypt(bob.encrypt(b"reply"))
    stolen = Ratchet(bob.ratchet.state.clone())  # A3 copies Bob's whole state
    assert not stolen.state.skipped  # no message keys left behind
    for m in past:
        with pytest.raises(ProtocolError):
            stolen.decrypt(m)


def test_skipped_keys_are_the_exposure_window() -> None:
    """Documents the known limit (T-24): keys of not-yet-arrived messages are in the state."""
    alice, bob = make_pair()
    late, on_time = alice.encrypt(b"late"), alice.encrypt(b"on time")
    bob.decrypt(on_time)
    stolen = Ratchet(bob.ratchet.state.clone())
    assert unpad(stolen.decrypt(late)) == b"late"  # the attacker reads the delayed message
