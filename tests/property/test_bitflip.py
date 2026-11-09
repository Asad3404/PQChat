"""SR-7 (Hypothesis): flipping any single bit of an initial message makes Bob reject it."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys
from pqchat.protocol.errors import ProtocolError
from tests.conftest import NOW, make_store

BOB = make_store()
MSG, _ = handshake.initiate(IdentityKeys.generate(), BOB.bundle(), b"attack at dawn", now=NOW)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(bit=st.integers(min_value=0, max_value=len(MSG) * 8 - 1))
def test_any_single_bit_flip_is_rejected(bit: int) -> None:
    tampered = bytearray(MSG)
    tampered[bit // 8] ^= 1 << (bit % 8)
    with pytest.raises(ProtocolError):
        handshake.respond(BOB, bytes(tampered), now=NOW)


def test_original_still_accepted_after_all_flips() -> None:
    """Rejected forgeries must not consume Bob's one-time prekeys."""
    assert handshake.respond(BOB, MSG, now=NOW).plaintext == b"attack at dawn"
