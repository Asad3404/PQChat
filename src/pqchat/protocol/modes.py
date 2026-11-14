"""Protocol modes and local policy (PROJECT-BRIEF.md §5.4, SR-6, SR-34)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from pqchat.crypto import labels

PROTOCOL_VERSION = 1


class Mode(IntEnum):
    CLASSICAL = 1  # X25519 only, Ed25519 authentication (X3DH-style)
    HYBRID = 2  # X25519 + ML-KEM-768, Ed25519 + ML-DSA-65 (default)
    PQ_ONLY = 3  # ML-KEM-768 only, ML-DSA-65, transcript signed by Alice (benchmark only)


class KexSuite(IntEnum):
    X25519 = 1
    X25519_MLKEM768 = 2
    MLKEM768 = 3


class SigSuite(IntEnum):
    ED25519 = 1
    ED25519_MLDSA65 = 2
    MLDSA65 = 3


class AeadSuite(IntEnum):
    AES256GCM_HKDF_SHA256 = 1


#: Each mode fixes its suite exactly; anything else is rejected.
SUITES: dict[Mode, tuple[KexSuite, SigSuite, AeadSuite]] = {
    Mode.CLASSICAL: (KexSuite.X25519, SigSuite.ED25519, AeadSuite.AES256GCM_HKDF_SHA256),
    Mode.HYBRID: (
        KexSuite.X25519_MLKEM768,
        SigSuite.ED25519_MLDSA65,
        AeadSuite.AES256GCM_HKDF_SHA256,
    ),
    Mode.PQ_ONLY: (KexSuite.MLKEM768, SigSuite.MLDSA65, AeadSuite.AES256GCM_HKDF_SHA256),
}

SK_INFO: dict[Mode, bytes] = {
    Mode.CLASSICAL: labels.HANDSHAKE_SK_CLASSICAL,
    Mode.HYBRID: labels.HANDSHAKE_SK,
    Mode.PQ_ONLY: labels.HANDSHAKE_SK_PQONLY,
}


def uses_dh(mode: Mode) -> bool:
    return mode is not Mode.PQ_ONLY


def uses_kem(mode: Mode) -> bool:
    return mode is not Mode.CLASSICAL


def uses_ed25519(mode: Mode) -> bool:
    return mode is not Mode.PQ_ONLY


def uses_mldsa(mode: Mode) -> bool:
    return mode is not Mode.CLASSICAL


@dataclass(frozen=True)
class Policy:
    """What this client is willing to do. The default is hybrid only."""

    allow_classical: bool = False
    allow_pq_only: bool = False
    #: Clock skew tolerated for prekey ``created_at`` (seconds).
    max_clock_skew: int = 300

    def allowed(self, mode: Mode) -> bool:
        if mode is Mode.HYBRID:
            return True
        if mode is Mode.CLASSICAL:
            return self.allow_classical
        return self.allow_pq_only
