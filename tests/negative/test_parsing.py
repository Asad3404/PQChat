"""SR-9: strict parsing rejects malformed input before any crypto runs."""

from __future__ import annotations

import pytest

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, IdentityPublic, PrekeyBundle, PrekeyStore
from pqchat.protocol.encoding import Reader, Writer
from pqchat.protocol.errors import ParseError, ProtocolError
from tests.conftest import NOW


@pytest.fixture
def msg(alice_identity: IdentityKeys, bob: PrekeyStore) -> bytes:
    return handshake.initiate(alice_identity, bob.bundle(), b"hello", now=NOW)[0]


@pytest.mark.parametrize("cut", [0, 1, 5, 40, 2000, 4000, -20, -1])
def test_truncated_initial_message(msg: bytes, bob: PrekeyStore, cut: int) -> None:
    with pytest.raises(ParseError):
        handshake.respond(bob, msg[:cut], now=NOW)


def test_trailing_bytes(msg: bytes, bob: PrekeyStore) -> None:
    with pytest.raises(ParseError):
        handshake.respond(bob, msg + b"\x00", now=NOW)


def test_oversized_message(bob: PrekeyStore) -> None:
    with pytest.raises(ParseError):
        handshake.respond(bob, b"\x01" * (handshake.MAX_INITIAL_MESSAGE + 1), now=NOW)


@pytest.mark.parametrize(
    ("offset", "value"),
    [(0, 2), (0, 0), (1, 9), (5, 0x09), (5 + 33, 0x01)],
    ids=["version-2", "version-0", "unknown-mode", "wrong-alg-id", "wrong-alg-id-2"],
)
def test_unknown_values(msg: bytes, bob: PrekeyStore, offset: int, value: int) -> None:
    tampered = msg[:offset] + bytes([value]) + msg[offset + 1 :]
    with pytest.raises(ProtocolError):
        handshake.respond(bob, tampered, now=NOW)


def test_unknown_header_flags(msg: bytes, bob: PrekeyStore) -> None:
    header, _, _ = handshake.parse_initial(msg)
    flags_at = 5 + len(header.identity.encode()) + 4 + 33
    tampered = msg[:flags_at] + bytes([msg[flags_at] | 0x80]) + msg[flags_at + 1 :]
    with pytest.raises(ParseError):
        handshake.respond(bob, tampered, now=NOW)


def test_bundle_parsing(bob: PrekeyStore) -> None:
    raw = bob.bundle().encode()
    for bad in (raw[:-1], raw + b"\x00", b"\x02" + raw[1:]):
        with pytest.raises(ParseError):
            PrekeyBundle.decode(bad)
    flags_at = 1 + len(bob.identity.public.encode())
    with pytest.raises(ParseError):
        PrekeyBundle.decode(raw[:flags_at] + b"\xf0" + raw[flags_at + 1 :])
    with pytest.raises(ParseError):  # prekey kind byte wrong
        PrekeyBundle.decode(raw[: flags_at + 1] + b"\x02" + raw[flags_at + 2 :])
    with pytest.raises(ParseError):
        IdentityPublic.decode(bob.identity.public.encode()[:-1])
    with pytest.raises(ParseError):
        PrekeyBundle.decode(b"\x01" * 40_000)


def test_reader_writer_limits() -> None:
    with pytest.raises(ValueError):
        Writer().u8(256)
    with pytest.raises(ValueError):
        Writer().raw(b"abc", 2)
    with pytest.raises(ValueError):
        Writer().var(b"x" * 11, 10)
    r = Reader(Writer().u16(11).getvalue() + b"x" * 11, 100)
    with pytest.raises(ParseError):
        r.var(10)
    big = Writer().var(b"y" * 70_000, 100_000).getvalue()
    assert Reader(big, 200_000).var(100_000) == b"y" * 70_000


def _pq_only(alice: IdentityKeys, bob: PrekeyStore) -> bytes:
    from pqchat.protocol.modes import Mode, Policy

    pol = Policy(allow_pq_only=True)
    return handshake.initiate(alice, bob.bundle(), b"x", mode=Mode.PQ_ONLY, policy=pol, now=NOW)[0]


def test_dh_flag_in_pq_only_mode_is_rejected(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    from pqchat.protocol.modes import Policy

    msg = _pq_only(alice_identity, bob)
    flags_at = 5 + len(alice_identity.public.encode()) + 4  # no EK in pq-only
    tampered = msg[:flags_at] + bytes([msg[flags_at] | 0x01]) + msg[flags_at + 1 :]
    with pytest.raises(ParseError):
        handshake.respond(bob, tampered, policy=Policy(allow_pq_only=True), now=NOW)


def test_pq_only_transcript_signature_tampered(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    from pqchat.protocol.errors import VerificationError
    from pqchat.protocol.modes import Policy

    msg = bytearray(_pq_only(alice_identity, bob))
    _, header_bytes, _ = handshake.parse_initial(bytes(msg))
    msg[len(header_bytes) - 10] ^= 1  # inside the ML-DSA transcript signature
    with pytest.raises(VerificationError, match="transcript"):
        handshake.respond(bob, bytes(msg), policy=Policy(allow_pq_only=True), now=NOW)


def test_kem_flag_in_classical_mode_is_rejected(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    from pqchat.protocol.modes import Mode, Policy

    pol = Policy(allow_classical=True)
    msg = handshake.initiate(
        alice_identity, bob.bundle(), b"x", mode=Mode.CLASSICAL, policy=pol, now=NOW
    )[0]
    flags_at = 5 + len(alice_identity.public.encode()) + 4 + 33
    tampered = msg[:flags_at] + bytes([msg[flags_at] | 0x02]) + msg[flags_at + 1 :]
    with pytest.raises(ParseError):
        handshake.respond(bob, tampered, policy=pol, now=NOW)


def test_low_order_ephemeral_key_is_a_verification_error(
    alice_identity: IdentityKeys, bob: PrekeyStore
) -> None:
    """An all-zero EK makes X25519 fail inside the crypto layer; Bob reports it as a
    protocol VerificationError and never leaks the internal CryptoError."""
    from pqchat.protocol.errors import VerificationError

    msg = handshake.initiate(alice_identity, bob.bundle(), b"x", now=NOW)[0]
    ek_at = 5 + len(alice_identity.public.encode()) + 4 + 1
    tampered = msg[:ek_at] + bytes(32) + msg[ek_at + 32 :]
    with pytest.raises(VerificationError):
        handshake.respond(bob, tampered, now=NOW)
