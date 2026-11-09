"""PQXDH-style hybrid handshake (PROJECT-BRIEF.md §5.2, docs/protocol-spec.md §4).

Initial message::

    header = version u8 | mode u8 | kex u8 | sig u8 | aead u8 | IdentityPublic(Alice)
             | spk_id u32 | [key(X25519) EK_A]                       (EK only if mode uses DH)
             | flags u8 (bit0: OPK used, bit1: PQ prekey is one-time)
             | [opk_id u32] | [pq_id u32 | CT[1088]]                  (CT only if mode uses KEM)
             | [transcript_sig[3309]]                                 (pq-only)
    message = header | u16 len | AES-256-GCM(k_msg, nonce = 0^96, plaintext, AD || header)

Key schedule::

    SK   = HKDF(salt = 0^32, ikm = F || DH1 || DH2 || DH3 [|| DH4] || SS, info = mode label)
    k_msg || RK = HKDF(salt = 0^32, ikm = SK, info = HANDSHAKE_SPLIT, 64 bytes)
    AD   = Encode(IK_A) || Encode(IK_B) || PB
    PB   = SHA-256(PREKEY_BINDING || flags || used prekey public keys)      (SR-37)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from pqchat.crypto import aead, kdf, labels
from pqchat.crypto.dh import X25519KeyPair
from pqchat.crypto.errors import CryptoError
from pqchat.crypto.kem import CIPHERTEXT_LEN, encapsulate
from pqchat.crypto.sig import MLDSA_SIG_LEN, mldsa_verify
from pqchat.crypto.zeroize import wipe
from pqchat.protocol.bundle import (
    MAX_SIGNED_PREKEY_LIFETIME,
    IdentityKeys,
    IdentityPublic,
    PrekeyBundle,
    PrekeyStore,
    SignedPrekey,
)
from pqchat.protocol.encoding import ALG_MLKEM768, ALG_X25519, Reader, Writer
from pqchat.protocol.errors import (
    DowngradeError,
    ParseError,
    ProtocolError,
    ReplayError,
    VerificationError,
)
from pqchat.protocol.modes import (
    PROTOCOL_VERSION,
    SK_INFO,
    SUITES,
    Mode,
    Policy,
    uses_dh,
    uses_kem,
)

F = b"\xff" * 32
ZERO_SALT = bytes(32)
ZERO_NONCE = bytes(aead.NONCE_LEN)
MAX_FIRST_PLAINTEXT = 16 * 1024
MAX_INITIAL_MESSAGE = 32 * 1024

FLAG_OPK = 0x01
FLAG_PQ_ONE_TIME = 0x02


@dataclass(frozen=True)
class InitialHeader:
    mode: Mode
    identity: IdentityPublic
    spk_id: int
    ek: bytes | None
    opk_id: int | None
    pq_id: int | None
    pq_one_time: bool
    ct: bytes | None
    transcript_sig: bytes | None = None

    def encode_unsigned(self) -> bytes:
        kex, sig, ae = SUITES[self.mode]
        w = Writer().u8(PROTOCOL_VERSION).u8(self.mode).u8(kex).u8(sig).u8(ae)
        ident = self.identity.encode()
        w.raw(ident, len(ident))
        w.u32(self.spk_id)
        if uses_dh(self.mode):
            if not (self.ek is not None):
                raise ProtocolError("internal state error")
            w.key(ALG_X25519, self.ek)
        flags = (FLAG_OPK if self.opk_id is not None else 0) | (
            FLAG_PQ_ONE_TIME if self.pq_one_time else 0
        )
        w.u8(flags)
        if self.opk_id is not None:
            w.u32(self.opk_id)
        if uses_kem(self.mode):
            if not (self.pq_id is not None and self.ct is not None):
                raise ProtocolError("internal state error")
            w.u32(self.pq_id).raw(self.ct, CIPHERTEXT_LEN)
        return w.getvalue()

    def encode(self) -> bytes:
        out = self.encode_unsigned()
        if self.mode is Mode.PQ_ONLY:
            if not (self.transcript_sig is not None):
                raise ProtocolError("internal state error")
            out += Writer().raw(self.transcript_sig, MLDSA_SIG_LEN).getvalue()
        return out

    @classmethod
    def read(cls, r: Reader) -> InitialHeader:
        if r.u8() != PROTOCOL_VERSION:
            raise ParseError("unsupported protocol version")
        try:
            mode = Mode(r.u8())
        except ValueError:
            raise ParseError("unknown mode") from None
        if (r.u8(), r.u8(), r.u8()) != tuple(int(x) for x in SUITES[mode]):
            raise DowngradeError("algorithm suite does not match mode")
        identity = IdentityPublic.read(r)
        spk_id = r.u32()
        ek = r.key(ALG_X25519) if uses_dh(mode) else None
        flags = r.u8()
        if flags & ~(FLAG_OPK | FLAG_PQ_ONE_TIME):
            raise ParseError("unknown header flags")
        if flags & FLAG_OPK and not uses_dh(mode):
            raise ParseError("one-time DH prekey in a mode without DH")
        if flags & FLAG_PQ_ONE_TIME and not uses_kem(mode):
            raise ParseError("KEM prekey flag in a mode without KEM")
        opk_id = r.u32() if flags & FLAG_OPK else None
        pq_id, ct = (r.u32(), r.raw(CIPHERTEXT_LEN)) if uses_kem(mode) else (None, None)
        header = cls(mode, identity, spk_id, ek, opk_id, pq_id, bool(flags & FLAG_PQ_ONE_TIME), ct)
        if mode is Mode.PQ_ONLY:
            header = InitialHeader(**{**header.__dict__, "transcript_sig": r.raw(MLDSA_SIG_LEN)})
        return header


@dataclass
class SessionInit:
    """What the handshake hands to the ratchet (M5)."""

    mode: Mode
    root_key: bytearray
    associated_data: bytes
    peer: IdentityPublic
    #: Alice: Bob's signed prekey (his first ratchet public key). Bob: that key pair.
    peer_ratchet_public: bytes | None = None
    own_ratchet_keypair: X25519KeyPair | None = None
    #: Bob's signed ML-KEM prekey, Alice's first PQ ratchet target (M5).
    peer_kem_public: bytes | None = None
    plaintext: bytes = b""


@dataclass
class ReplayCache:
    """Hashes of accepted initial-message headers, kept until they can no longer verify (SR-11)."""

    seen: dict[bytes, int] = field(default_factory=dict)

    def check(self, header: bytes) -> bytes:
        digest = kdf.sha256(header)
        if digest in self.seen:
            raise ReplayError("initial message replayed")
        return digest

    def add(self, digest: bytes, now: int) -> None:
        self.seen[digest] = now + MAX_SIGNED_PREKEY_LIFETIME

    def purge(self, now: int) -> None:
        for digest in [d for d, until in self.seen.items() if until <= now]:
            del self.seen[digest]


# ----------------------------------------------------------------------------- shared
def _derive(
    mode: Mode, dh_outputs: list[bytearray], ss: bytearray | None
) -> tuple[bytearray, bytearray]:
    ikm = bytearray(F)
    for part in dh_outputs:
        ikm += part
    if ss is not None:
        ikm += ss
    sk = kdf.hkdf(ikm, ZERO_SALT, SK_INFO[mode], 32)
    okm = kdf.hkdf(sk, ZERO_SALT, labels.HANDSHAKE_SPLIT, 64)
    msg_key, root_key = bytearray(okm[:32]), bytearray(okm[32:])
    wipe(ikm, sk, okm, ss, *dh_outputs)
    return msg_key, root_key


def prekey_binding(
    flags: int, spk: SignedPrekey, opk: SignedPrekey | None, pq: SignedPrekey | None
) -> bytes:
    w = Writer().u8(flags).key(ALG_X25519, spk.public)
    if opk is not None:
        w.key(ALG_X25519, opk.public)
    if pq is not None:
        w.key(ALG_MLKEM768, pq.public)
    return kdf.sha256(labels.PREKEY_BINDING, w.getvalue())


def associated_data(alice: IdentityPublic, bob: IdentityPublic, binding: bytes) -> bytes:
    return alice.encode() + bob.encode() + binding


def _transcript(header_unsigned: bytes, bob: IdentityPublic) -> bytes:
    return header_unsigned + bob.encode()


# ----------------------------------------------------------------------------- Alice
def initiate(
    alice: IdentityKeys,
    bundle: PrekeyBundle,
    plaintext: bytes,
    *,
    mode: Mode = Mode.HYBRID,
    policy: Policy | None = None,
    now: int | None = None,
) -> tuple[bytes, SessionInit]:
    policy = policy or Policy()
    now = int(time.time()) if now is None else now
    if len(plaintext) > MAX_FIRST_PLAINTEXT:
        raise ValueError("first message too long")
    bundle.verify(mode, now, policy)

    spk = bundle.spk
    opk = bundle.opk if uses_dh(mode) else None
    pq = bundle.pq_prekey() if uses_kem(mode) else None

    dh_outputs: list[bytearray] = []
    ek: X25519KeyPair | None = None
    if uses_dh(mode):
        ek = X25519KeyPair.generate()
        dh_outputs = [
            alice.dh.dh(spk.public),
            ek.dh(bundle.identity.dh),
            ek.dh(spk.public),
        ]
        if opk is not None:
            dh_outputs.append(ek.dh(opk.public))
    ct: bytes | None = None
    ss: bytearray | None = None
    if pq is not None:
        ct, ss = encapsulate(pq.public)

    header = InitialHeader(
        mode=mode,
        identity=alice.public,
        spk_id=spk.key_id,
        ek=ek.public if ek else None,
        opk_id=opk.key_id if opk else None,
        pq_id=pq.key_id if pq else None,
        pq_one_time=pq is not None and pq is bundle.pqopk,
        ct=ct,
    )
    if mode is Mode.PQ_ONLY:
        sig = alice.signing.sign_mldsa(
            labels.SIG_TRANSCRIPT_PQONLY, _transcript(header.encode_unsigned(), bundle.identity)
        )
        header = InitialHeader(**{**header.__dict__, "transcript_sig": sig})
    header_bytes = header.encode()

    msg_key, root_key = _derive(mode, dh_outputs, ss)
    flags = (FLAG_OPK if opk else 0) | (FLAG_PQ_ONE_TIME if header.pq_one_time else 0)
    ad = associated_data(alice.public, bundle.identity, prekey_binding(flags, spk, opk, pq))
    try:
        body = aead.seal(msg_key, ZERO_NONCE, plaintext, ad + header_bytes)
    finally:
        wipe(msg_key)
    message = header_bytes + Writer().var(body, MAX_FIRST_PLAINTEXT + aead.TAG_LEN).getvalue()
    return message, SessionInit(
        mode=mode,
        root_key=root_key,
        associated_data=ad,
        peer=bundle.identity,
        peer_ratchet_public=spk.public,
        peer_kem_public=bundle.pqspk.public if bundle.pqspk else None,
    )


# ----------------------------------------------------------------------------- Bob
def parse_initial(message: bytes) -> tuple[InitialHeader, bytes, bytes]:
    """Strictly parse an initial message: (header, header_bytes, ciphertext)."""
    r = Reader(message, MAX_INITIAL_MESSAGE)
    header = InitialHeader.read(r)
    header_bytes = r.consumed()
    body = r.var(MAX_FIRST_PLAINTEXT + aead.TAG_LEN)
    r.end()
    return header, header_bytes, body


def respond(
    bob: PrekeyStore,
    message: bytes,
    *,
    policy: Policy | None = None,
    replay_cache: ReplayCache | None = None,
    now: int | None = None,
) -> SessionInit:
    """Process Alice's initial message. Every failure is a ProtocolError subclass."""
    try:
        return _respond(bob, message, policy, replay_cache, now)
    except CryptoError:
        raise VerificationError("initial message rejected") from None


def _respond(
    bob: PrekeyStore,
    message: bytes,
    policy: Policy | None,
    replay_cache: ReplayCache | None,
    now: int | None,
) -> SessionInit:
    policy = policy or Policy()
    now = int(time.time()) if now is None else now
    header, header_bytes, body = parse_initial(message)  # 1. strict parsing first
    mode = header.mode
    if not policy.allowed(mode):  # 2. local policy (SR-6)
        raise DowngradeError("mode not allowed by local policy")
    header.identity.verify(mode)  # 3. Alice's identity signatures
    digest = replay_cache.check(header_bytes) if replay_cache else None  # 4. SR-11

    if mode is Mode.PQ_ONLY:
        if not (header.transcript_sig is not None):
            raise ProtocolError("internal state error")
        if not mldsa_verify(
            header.identity.sign.mldsa65,
            header.transcript_sig,
            labels.SIG_TRANSCRIPT_PQONLY,
            _transcript(header.encode_unsigned(), bob.identity.public),
        ):
            raise VerificationError("transcript signature invalid")

    spk_pair = bob.signed_dh_key(header.spk_id)
    spk_rec = bob.public_record(header.spk_id, ALG_X25519, one_time=False)
    if now >= spk_rec.expires_at:
        raise VerificationError("signed prekey expired")
    opk_rec: SignedPrekey | None = None
    dh_outputs: list[bytearray] = []
    if uses_dh(mode):
        if not (header.ek is not None):
            raise ProtocolError("internal state error")
        dh_outputs = [
            spk_pair.dh(header.identity.dh),
            bob.identity.dh.dh(header.ek),
            spk_pair.dh(header.ek),
        ]
        if header.opk_id is not None:
            dh_outputs.append(bob.one_time_dh_key(header.opk_id).dh(header.ek))
            opk_rec = bob.public_record(header.opk_id, ALG_X25519, one_time=True)

    pq_rec: SignedPrekey | None = None
    ss: bytearray | None = None
    if uses_kem(mode):
        if not (header.pq_id is not None and header.ct is not None):
            raise ProtocolError("internal state error")
        kem = bob.kem_key(header.pq_id, header.pq_one_time)
        pq_rec = bob.public_record(header.pq_id, ALG_MLKEM768, header.pq_one_time)
        ss = kem.decapsulate(header.ct)

    msg_key, root_key = _derive(mode, dh_outputs, ss)
    flags = (FLAG_OPK if header.opk_id is not None else 0) | (
        FLAG_PQ_ONE_TIME if header.pq_one_time else 0
    )
    ad = associated_data(
        header.identity, bob.identity.public, prekey_binding(flags, spk_rec, opk_rec, pq_rec)
    )
    try:
        plaintext = aead.open_(msg_key, ZERO_NONCE, body, ad + header_bytes)
    except CryptoError:
        wipe(root_key)
        raise VerificationError("initial message failed authentication") from None
    finally:
        wipe(msg_key)

    # Only now, after authentication: burn one-time prekeys and remember the message.
    bob.consume_one_time(header.opk_id, header.pq_id if header.pq_one_time else None)
    if replay_cache is not None and digest is not None:
        replay_cache.add(digest, now)
    return SessionInit(
        mode=mode,
        root_key=root_key,
        associated_data=ad,
        peer=header.identity,
        own_ratchet_keypair=spk_pair,
        plaintext=plaintext,
    )
