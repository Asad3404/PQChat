"""Passphrase-based encryption of the private key store (SR-26, PROJECT-BRIEF.md §3.10).

Format (all integers big-endian)::

    magic "PQKS" | version u8 | m_cost_kib u32 | t_cost u8 | parallelism u8 | salt 16 | nonce 12
    | AES-256-GCM(key, plaintext, ad = KEYSTORE_AD || header)

Key = Argon2id(passphrase, salt, m, t, p, 32 bytes). Parameters are part of the AEAD
associated data, and anything below the minimum is refused before Argon2 runs, so an
attacker cannot weaken the parameters in a stolen file to speed up guessing.
"""

from __future__ import annotations

import os
import struct

from argon2.low_level import Type, hash_secret_raw

from pqchat.crypto import aead
from pqchat.crypto.errors import CryptoError
from pqchat.crypto.labels import KEYSTORE_AD
from pqchat.crypto.zeroize import wipe

MAGIC = b"PQKS"
VERSION = 1
SALT_LEN = 16
#: RFC 9106 §4, second recommended option.
DEFAULT_M_COST_KIB = 64 * 1024
DEFAULT_T_COST = 3
DEFAULT_PARALLELISM = 4
MIN_M_COST_KIB = DEFAULT_M_COST_KIB
MIN_T_COST = DEFAULT_T_COST
MAX_M_COST_KIB = 4 * 1024 * 1024  # refuse absurd values that would exhaust memory
MAX_T_COST = 32
_HEADER = struct.Struct(">4sBIBB16s12s")
HEADER_LEN = _HEADER.size


def _derive(passphrase: str, salt: bytes, m: int, t: int, p: int) -> bytearray:
    return bytearray(
        hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=t,
            memory_cost=m,
            parallelism=p,
            hash_len=aead.KEY_LEN,
            type=Type.ID,
        )
    )


def encrypt_keystore(passphrase: str, plaintext: bytes) -> bytes:
    if not passphrase:
        raise CryptoError("empty passphrase")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(aead.NONCE_LEN)
    header = _HEADER.pack(
        MAGIC, VERSION, DEFAULT_M_COST_KIB, DEFAULT_T_COST, DEFAULT_PARALLELISM, salt, nonce
    )
    key = _derive(passphrase, salt, DEFAULT_M_COST_KIB, DEFAULT_T_COST, DEFAULT_PARALLELISM)
    try:
        return header + aead.seal(key, nonce, plaintext, KEYSTORE_AD + header)
    finally:
        wipe(key)


def decrypt_keystore(passphrase: str, blob: bytes) -> bytes:
    if len(blob) < HEADER_LEN + aead.TAG_LEN:
        raise CryptoError("key store file is truncated")
    header = bytes(blob[:HEADER_LEN])
    magic, version, m, t, p, salt, nonce = _HEADER.unpack(header)
    if magic != MAGIC or version != VERSION:
        raise CryptoError("not a PQ-Chat key store, or unsupported version")
    if not (
        MIN_M_COST_KIB <= m <= MAX_M_COST_KIB and MIN_T_COST <= t <= MAX_T_COST and 1 <= p <= 16
    ):
        raise CryptoError("key store parameters are outside the allowed range")
    key = _derive(passphrase, salt, m, t, p)
    try:
        return aead.open_(key, nonce, bytes(blob[HEADER_LEN:]), KEYSTORE_AD + header)
    except CryptoError as exc:
        raise CryptoError("wrong passphrase or corrupted key store") from exc
    finally:
        wipe(key)
