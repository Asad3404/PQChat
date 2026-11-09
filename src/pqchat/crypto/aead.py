"""AES-256-GCM via pyca/cryptography."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqchat.crypto.errors import CryptoError

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def _check(key: bytes | bytearray, nonce: bytes) -> None:
    if len(key) != KEY_LEN:
        raise CryptoError("AES-256-GCM key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise CryptoError("AES-GCM nonce must be 12 bytes")


def seal(key: bytes | bytearray, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    """Encrypt and authenticate. Returns ciphertext || 16-byte tag.

    The caller must never use the same (key, nonce) twice; PQ-Chat uses every key once.
    """
    _check(key, nonce)
    return AESGCM(bytes(key)).encrypt(bytes(nonce), bytes(plaintext), bytes(ad))


def open_(key: bytes | bytearray, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    """Verify and decrypt. Raises CryptoError if anything was modified."""
    _check(key, nonce)
    if len(ciphertext) < TAG_LEN:
        raise CryptoError("ciphertext too short")
    try:
        return AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), bytes(ad))
    except InvalidTag as exc:
        raise CryptoError("authentication failed") from exc
