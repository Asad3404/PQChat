"""Any single bit flip in a ratchet message is rejected and leaves the session usable."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqchat.protocol.errors import ProtocolError
from tests.conftest import make_pair

ALICE, BOB = make_pair()
BOB.decrypt(ALICE.encrypt(b"warm-up"))
REPLY = BOB.encrypt(b"bob reply")  # first message of a new DH chain, includes KEM announcement


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(bit=st.integers(min_value=0, max_value=len(REPLY) * 8 - 1))
def test_bit_flip_rejected(bit: int) -> None:
    bad = bytearray(REPLY)
    bad[bit // 8] ^= 1 << (bit % 8)
    with pytest.raises(ProtocolError):
        ALICE.decrypt(bytes(bad))


def test_state_unchanged_by_forgeries() -> None:
    assert ALICE.decrypt(REPLY) == b"bob reply"
