"""Registry of every domain-separation label (SR-16, PROJECT-BRIEF.md §3.7).

Each HKDF ``info``, HMAC input prefix and signature label used anywhere in PQ-Chat is
defined here, once. ``tests/unit/test_labels.py`` checks that they are unique and all start
with ``PQChat-v1``, so two different uses can never produce the same derived value.
"""

from __future__ import annotations

PREFIX = b"PQChat-v1"

# --- Handshake (M3) -------------------------------------------------------------------
#: HKDF info for the session key SK, exactly as in PROJECT-BRIEF.md §5.2 step 4.
HANDSHAKE_SK = b"PQChat-v1 X25519 MLKEM768 SHA256 AES256GCM"
#: Same for the benchmark-only modes, so keys from different modes can never coincide.
HANDSHAKE_SK_CLASSICAL = b"PQChat-v1 X25519 SHA256 AES256GCM"
HANDSHAKE_SK_PQONLY = b"PQChat-v1 MLKEM768 SHA256 AES256GCM"
#: HKDF info to split SK into the first-message AEAD key and the initial root key.
HANDSHAKE_SPLIT = b"PQChat-v1 handshake split"

# --- Signatures -------------------------------------------------------------------------
SIG_IDENTITY_DH = b"PQChat-v1 sig identity-dh"
SIG_PREKEY = b"PQChat-v1 sig prekey"
SIG_TRANSCRIPT_PQONLY = b"PQChat-v1 sig pq-only transcript"
SIG_RELAY_AUTH = b"PQChat-v1 sig relay-auth"

# --- Double ratchet (M5) ----------------------------------------------------------------
RATCHET_ROOT = b"PQChat-v1 ratchet root"
RATCHET_ROOT_PQ = b"PQChat-v1 ratchet root pq"
RATCHET_CHAIN_MSG = b"PQChat-v1 ratchet chain message"
RATCHET_CHAIN_NEXT = b"PQChat-v1 ratchet chain next"
RATCHET_MSG_KEYS = b"PQChat-v1 ratchet message keys"

# --- Key store, history, safety numbers -------------------------------------------------
KEYSTORE_AD = b"PQChat-v1 keystore"
HISTORY_KEY = b"PQChat-v1 history key"
SAFETY_NUMBER = b"PQChat-v1 safety number"
PREKEY_BINDING = b"PQChat-v1 prekey binding"

ALL: tuple[bytes, ...] = (
    HANDSHAKE_SK,
    HANDSHAKE_SK_CLASSICAL,
    HANDSHAKE_SK_PQONLY,
    HANDSHAKE_SPLIT,
    SIG_IDENTITY_DH,
    SIG_PREKEY,
    SIG_TRANSCRIPT_PQONLY,
    SIG_RELAY_AUTH,
    RATCHET_ROOT,
    RATCHET_ROOT_PQ,
    RATCHET_CHAIN_MSG,
    RATCHET_CHAIN_NEXT,
    RATCHET_MSG_KEYS,
    KEYSTORE_AD,
    HISTORY_KEY,
    SAFETY_NUMBER,
    PREKEY_BINDING,
)
