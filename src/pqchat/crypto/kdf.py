"""HKDF-SHA256 (RFC 5869) and HMAC-SHA256 (RFC 2104) via pyca/cryptography."""

from __future__ import annotations

import hmac as _hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _pyca_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pqchat.crypto.errors import CryptoError

HASH_LEN = 32
MAX_OKM = 255 * HASH_LEN


def hkdf(ikm: bytes | bytearray, salt: bytes, info: bytes, length: int) -> bytearray:
    """Derive ``length`` bytes. Returned as a ``bytearray`` so the caller can wipe it."""
    if not 1 <= length <= MAX_OKM:
        raise CryptoError("invalid HKDF output length")
    okm = HKDF(algorithm=hashes.SHA256(), length=length, salt=bytes(salt), info=bytes(info)).derive(
        bytes(ikm)
    )
    return bytearray(okm)


def hmac_sha256(key: bytes | bytearray, data: bytes) -> bytearray:
    mac = _pyca_hmac.HMAC(bytes(key), hashes.SHA256())
    mac.update(bytes(data))
    return bytearray(mac.finalize())


def sha256(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of ``parts`` (callers pass a label first)."""
    digest = hashes.Hash(hashes.SHA256())
    for part in parts:
        digest.update(bytes(part))
    return digest.finalize()


def verify_hmac(key: bytes | bytearray, data: bytes, tag: bytes) -> bool:
    """Constant-time tag comparison (SR-3)."""
    return _hmac.compare_digest(bytes(hmac_sha256(key, data)), bytes(tag))
