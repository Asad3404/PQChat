"""Length hiding: pad plaintext to fixed size buckets before encryption (SR-24, PROJECT-BRIEF.md §5.5).

Scheme: ISO/IEC 7816-4 — append one 0x80 byte, then zero bytes up to the bucket size. Unpadding
strips trailing zeros and requires exactly one 0x80 marker; anything else is rejected. Only the
bucket (256 / 1024 / 4096 / 16384 / 65536 bytes) is visible to the relay, not the exact length.
"""

from __future__ import annotations

from pqchat.protocol.errors import ParseError

BUCKETS = (256, 1024, 4096, 16 * 1024, 64 * 1024)
MAX_UNPADDED = BUCKETS[-1] - 1


def bucket_for(length: int) -> int:
    for size in BUCKETS:
        if length < size:
            return size
    raise ValueError("message too long to pad")


def pad(data: bytes) -> bytes:
    size = bucket_for(len(data))
    return data + b"\x80" + bytes(size - len(data) - 1)


def unpad(data: bytes) -> bytes:
    if len(data) not in BUCKETS:
        raise ParseError("padded message has an invalid size")
    end = len(data.rstrip(b"\x00"))
    if end == 0 or data[end - 1] != 0x80:
        raise ParseError("invalid padding")
    return data[: end - 1]
