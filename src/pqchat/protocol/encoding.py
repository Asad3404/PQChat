"""Strict binary encoding (CLAUDE.md §5.5, SR-8, SR-9).

* Integers are big-endian and range-checked.
* Every public key is written as ``alg_id || key`` with the exact length for that algorithm.
* Variable-length fields carry a u16/u32 length prefix and a fixed maximum.
* ``Reader.end()`` rejects trailing bytes, so every valid message has exactly one encoding.

All checks happen here, *before* any cryptographic operation sees the data.
"""

from __future__ import annotations

import struct

from pqchat.protocol.errors import ParseError

# Algorithm identifiers (one byte each). Never reuse a value.
ALG_X25519 = 0x01
ALG_ED25519 = 0x02
ALG_MLKEM768 = 0x03
ALG_MLDSA65 = 0x04

KEY_LENGTHS: dict[int, int] = {
    ALG_X25519: 32,
    ALG_ED25519: 32,
    ALG_MLKEM768: 1184,
    ALG_MLDSA65: 1952,
}


class Writer:
    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def _int(self, fmt: str, value: int, bits: int) -> Writer:
        if not 0 <= value < (1 << bits):
            raise ValueError(f"value out of range for u{bits}")
        self._buf += struct.pack(fmt, value)
        return self

    def u8(self, value: int) -> Writer:
        return self._int(">B", value, 8)

    def u16(self, value: int) -> Writer:
        return self._int(">H", value, 16)

    def u32(self, value: int) -> Writer:
        return self._int(">I", value, 32)

    def u64(self, value: int) -> Writer:
        return self._int(">Q", value, 64)

    def raw(self, data: bytes, length: int) -> Writer:
        if len(data) != length:
            raise ValueError(f"field must be exactly {length} bytes")
        self._buf += data
        return self

    def var(self, data: bytes, max_len: int) -> Writer:
        if len(data) > max_len:
            raise ValueError(f"field longer than {max_len} bytes")
        if max_len <= 0xFFFF:
            self.u16(len(data))
        else:
            self.u32(len(data))
        self._buf += data
        return self

    def key(self, alg: int, data: bytes) -> Writer:
        self.u8(alg)
        return self.raw(data, KEY_LENGTHS[alg])

    def getvalue(self) -> bytes:
        return bytes(self._buf)


class Reader:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes, max_total: int) -> None:
        if len(data) > max_total:
            raise ParseError(f"input larger than {max_total} bytes")
        self._data = bytes(data)
        self._pos = 0

    def _take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise ParseError("input truncated")
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def u8(self) -> int:
        return int(self._take(1)[0])

    def u16(self) -> int:
        return int(struct.unpack(">H", self._take(2))[0])

    def u32(self) -> int:
        return int(struct.unpack(">I", self._take(4))[0])

    def u64(self) -> int:
        return int(struct.unpack(">Q", self._take(8))[0])

    def raw(self, length: int) -> bytes:
        return self._take(length)

    def var(self, max_len: int) -> bytes:
        n = self.u16() if max_len <= 0xFFFF else self.u32()
        if n > max_len:
            raise ParseError(f"field longer than {max_len} bytes")
        return self._take(n)

    def key(self, expected_alg: int) -> bytes:
        alg = self.u8()
        if alg != expected_alg:
            raise ParseError("unexpected algorithm identifier")
        return self._take(KEY_LENGTHS[alg])

    def consumed(self) -> bytes:
        """Everything read so far (used to sign or authenticate a prefix)."""
        return self._data[: self._pos]

    def end(self) -> None:
        if self._pos != len(self._data):
            raise ParseError("unexpected trailing bytes")
