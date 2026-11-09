"""SR-24: padding is reversible and only reveals the bucket."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pqchat.protocol.errors import ParseError
from pqchat.protocol.padding import BUCKETS, MAX_UNPADDED, pad, unpad


@given(st.binary(max_size=5000))
def test_roundtrip_and_bucket_sizes(data: bytes) -> None:
    padded = pad(data)
    assert len(padded) in BUCKETS
    assert unpad(padded) == data


def test_lengths_within_a_bucket_are_indistinguishable() -> None:
    assert {len(pad(b"x" * n)) for n in range(256)} == {256}
    assert len(pad(b"x" * 255)) == 256 and len(pad(b"x" * 256)) == 1024


@pytest.mark.parametrize(
    "bad",
    [b"", b"\x00" * 256, b"x" * 255 + b"\x01", b"\x80" * 10, b"abc\x80" + bytes(252) + b"\x01"],
    ids=["empty", "no-marker", "bad-marker", "wrong-size", "trailing-garbage"],
)
def test_invalid_padding_rejected(bad: bytes) -> None:
    with pytest.raises(ParseError):
        unpad(bad)


def test_too_long() -> None:
    pad(b"x" * MAX_UNPADDED)
    with pytest.raises(ValueError):
        pad(b"x" * (MAX_UNPADDED + 1))


def test_session_ciphertexts_reveal_only_bucket() -> None:
    from tests.conftest import make_pair

    alice, bob = make_pair()
    sizes = {len(alice.encrypt(b"a" * n)) for n in (1, 50, 200, 255)}
    assert len(sizes) == 1  # 1 byte and 255 bytes look the same on the wire
    assert bob.decrypt(alice.encrypt("héllo".encode())) == "héllo".encode()
