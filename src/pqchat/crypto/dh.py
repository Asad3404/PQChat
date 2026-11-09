"""X25519 key agreement (RFC 7748) via pyca/cryptography."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from pqchat.crypto.errors import CryptoError

KEY_LEN = 32


def _check_len(data: bytes, name: str) -> None:
    if len(data) != KEY_LEN:
        raise CryptoError(f"{name} must be {KEY_LEN} bytes")


@dataclass(frozen=True)
class X25519KeyPair:
    _private: X25519PrivateKey
    public: bytes

    @classmethod
    def generate(cls) -> X25519KeyPair:
        priv = X25519PrivateKey.generate()
        return cls(priv, priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    @classmethod
    def from_private_bytes(cls, data: bytes) -> X25519KeyPair:
        _check_len(data, "X25519 private key")
        priv = X25519PrivateKey.from_private_bytes(bytes(data))
        return cls(priv, priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def private_bytes(self) -> bytearray:
        return bytearray(
            self._private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )

    def dh(self, peer_public: bytes) -> bytearray:
        """Return X25519(self, peer). Rejects low-order peer keys (all-zero output)."""
        _check_len(peer_public, "X25519 public key")
        try:
            shared = self._private.exchange(X25519PublicKey.from_public_bytes(bytes(peer_public)))
        except ValueError as exc:  # pyca raises on an all-zero shared secret
            raise CryptoError("X25519 produced an invalid shared secret") from exc
        return bytearray(shared)
