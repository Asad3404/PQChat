"""Hypothesis: decrypt(encrypt(m)) == m under reordering and loss (CLAUDE.md §8)."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests.conftest import make_pair

turn = st.tuples(
    st.integers(min_value=1, max_value=5),  # messages in this turn
    st.randoms(use_true_random=False),  # permutation source
    st.lists(st.booleans(), min_size=5, max_size=5),  # which messages are dropped
)


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(turns=st.lists(turn, min_size=1, max_size=8), payload=st.binary(max_size=64))
def test_out_of_order_and_dropped(turns: list, payload: bytes) -> None:  # type: ignore[type-arg]
    alice, bob = make_pair()
    for i, (count, rnd, drops) in enumerate(turns):
        sender, receiver = (alice, bob) if i % 2 == 0 else (bob, alice)
        sent = [(sender.encrypt(payload + bytes([j])), payload + bytes([j])) for j in range(count)]
        delivered = [m for k, m in enumerate(sent) if not drops[k]] or sent[:1]
        rnd.shuffle(delivered)
        for wire, plain in delivered:
            assert receiver.decrypt(wire) == plain
