"""SR-8 (Hypothesis): encoding is lossless and canonical."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pqchat.protocol.encoding import Reader, Writer


@given(
    a=st.integers(0, 255),
    b=st.integers(0, 2**16 - 1),
    c=st.integers(0, 2**32 - 1),
    d=st.integers(0, 2**64 - 1),
    blob=st.binary(max_size=300),
    key=st.binary(min_size=32, max_size=32),
)
def test_roundtrip(a: int, b: int, c: int, d: int, blob: bytes, key: bytes) -> None:
    data = Writer().u8(a).u16(b).u32(c).u64(d).var(blob, 300).key(0x01, key).getvalue()
    r = Reader(data, 10_000)
    assert (r.u8(), r.u16(), r.u32(), r.u64(), r.var(300), r.key(0x01)) == (a, b, c, d, blob, key)
    r.end()


@given(x=st.binary(max_size=50), y=st.binary(max_size=50))
def test_length_prefix_prevents_ambiguity(x: bytes, y: bytes) -> None:
    """('ab','c') and ('a','bc') must encode differently."""
    enc = Writer().var(x, 50).var(y, 50).getvalue()
    r = Reader(enc, 200)
    assert (r.var(50), r.var(50)) == (x, y)
