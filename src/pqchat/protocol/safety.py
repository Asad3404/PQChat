"""Safety numbers (SR-17): a short, comparable fingerprint of two users' identity keys.

Each user's half is 30 digits derived from SHA-256 over their full identity encoding
(Ed25519, ML-DSA-65 and X25519 public keys). The two halves are sorted, so both users see
the same 60 digits. Comparing them out of band detects a relay that substituted keys (T-02).
"""

from __future__ import annotations

from pqchat.crypto import kdf, labels
from pqchat.protocol.bundle import IdentityPublic

GROUPS_PER_USER = 6
DIGITS_PER_GROUP = 5


def _half(identity: IdentityPublic) -> str:
    digest = kdf.sha256(labels.SAFETY_NUMBER, identity.signed_part())
    groups = []
    for i in range(GROUPS_PER_USER):
        chunk = int.from_bytes(digest[i * 5 : i * 5 + 5], "big")
        groups.append(f"{chunk % 10**DIGITS_PER_GROUP:05d}")
    return "".join(groups)


def safety_number(a: IdentityPublic, b: IdentityPublic) -> str:
    """60 digits, identical for both users."""
    return "".join(sorted((_half(a), _half(b))))


def format_groups(number: str) -> list[str]:
    return [number[i : i + DIGITS_PER_GROUP] for i in range(0, len(number), DIGITS_PER_GROUP)]
