"""SR-16: every KDF/HMAC/signature label is unique and namespaced."""

from __future__ import annotations

from pqchat.crypto import labels


def test_labels_unique_and_prefixed() -> None:
    assert len(set(labels.ALL)) == len(labels.ALL)
    assert all(label.startswith(labels.PREFIX) for label in labels.ALL)


def test_registry_contains_every_module_constant() -> None:
    constants = {
        v for k, v in vars(labels).items() if k.isupper() and isinstance(v, bytes) and k != "PREFIX"
    }
    assert constants == set(labels.ALL)


def test_handshake_info_matches_spec() -> None:
    """CLAUDE.md §5.2 step 4 fixes this exact string."""
    assert labels.HANDSHAKE_SK == b"PQChat-v1 X25519 MLKEM768 SHA256 AES256GCM"
