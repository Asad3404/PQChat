"""SR-33: the client knows when messages are missing."""

from __future__ import annotations

from tests.conftest import make_pair


def test_gap_detected_and_closed() -> None:
    alice, bob = make_pair()
    m0, m1, m2 = (alice.encrypt(bytes([i])) for i in range(3))
    bob.decrypt(m0)
    bob.decrypt(m2)
    assert bob.missing_messages == 1
    bob.decrypt(m1)
    assert bob.missing_messages == 0
