"""Encrypted key store (SR-26)."""

from __future__ import annotations

import struct

import pytest

from pqchat.crypto import keystore_crypto as ks
from pqchat.crypto.errors import CryptoError


@pytest.fixture(scope="module")
def blob() -> bytes:
    return ks.encrypt_keystore("correct horse battery staple", b"private keys")


def test_roundtrip(blob: bytes) -> None:
    assert ks.decrypt_keystore("correct horse battery staple", blob) == b"private keys"


def test_parameters_meet_rfc9106(blob: bytes) -> None:
    _, _, m, t, p, _, _ = struct.unpack(">4sBIBB16s12s", blob[: ks.HEADER_LEN])
    assert (m, t, p) == (64 * 1024, 3, 4)


def test_wrong_passphrase(blob: bytes) -> None:
    with pytest.raises(CryptoError, match="wrong passphrase"):
        ks.decrypt_keystore("wrong", blob)


def test_tampered_header_is_detected(blob: bytes) -> None:
    """Changing the salt (part of the AD) must fail, not decrypt with another key."""
    bad = bytearray(blob)
    bad[12] ^= 1  # inside the salt
    with pytest.raises(CryptoError):
        ks.decrypt_keystore("correct horse battery staple", bytes(bad))


def test_weakened_parameters_are_refused_before_argon2(blob: bytes) -> None:
    weak = struct.pack(">4sBIBB", b"PQKS", 1, 8, 1, 1) + blob[11:]
    with pytest.raises(CryptoError, match="outside the allowed range"):
        ks.decrypt_keystore("correct horse battery staple", weak)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:20],
        lambda b: b"XXXX" + b[4:],
        lambda b: b[:4] + b"\x02" + b[5:],
    ],
    ids=["truncated", "bad-magic", "bad-version"],
)
def test_malformed_files(blob: bytes, mutate: object) -> None:
    with pytest.raises(CryptoError):
        ks.decrypt_keystore("x", mutate(blob))  # type: ignore[operator]


def test_empty_passphrase_refused() -> None:
    with pytest.raises(CryptoError):
        ks.encrypt_keystore("", b"x")
