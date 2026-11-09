"""Double ratchet (Signal spec) with ML-KEM re-keying (PROJECT-BRIEF.md §5.3, docs/notes/m5-pq-ratchet.md).

Message = header || u32 len || AES-256-GCM(message key, plaintext, AD || header)

header  = version u8 | flags u8 | key(X25519, DHs) | PN u32 | N u32 | kem_ack u32
          [| target_kem_id u32 | CT[1088]]               flags & 0x01  (ML-KEM re-key)
          [| own_kem_id u32 | key(MLKEM768, public)]     flags & 0x02  (KEM key announcement)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from pqchat.crypto import aead, kdf, labels
from pqchat.crypto.dh import X25519KeyPair
from pqchat.crypto.errors import CryptoError
from pqchat.crypto.kem import CIPHERTEXT_LEN
from pqchat.crypto.zeroize import wipe
from pqchat.protocol.encoding import ALG_MLKEM768, ALG_X25519, Reader, Writer
from pqchat.protocol.errors import ParseError, ProtocolError, ReplayError, VerificationError
from pqchat.protocol.modes import PROTOCOL_VERSION
from pqchat.protocol.pq_ratchet import KemRatchet

DhFactory = Callable[[], X25519KeyPair]

MAX_SKIP = 1000
MAX_PLAINTEXT = 64 * 1024
MAX_MESSAGE = MAX_PLAINTEXT + 4096
FLAG_KEM_CT = 0x01
FLAG_KEM_PUB = 0x02
ZERO_SALT = bytes(32)


# ------------------------------------------------------------------------------ header
@dataclass(frozen=True)
class Header:
    dh: bytes
    pn: int
    n: int
    kem_ack: int = 0
    kem_ct: tuple[int, bytes] | None = None
    kem_pub: tuple[int, bytes] | None = None

    def encode(self) -> bytes:
        flags = (FLAG_KEM_CT if self.kem_ct else 0) | (FLAG_KEM_PUB if self.kem_pub else 0)
        w = Writer().u8(PROTOCOL_VERSION).u8(flags).key(ALG_X25519, self.dh)
        w.u32(self.pn).u32(self.n).u32(self.kem_ack)
        if self.kem_ct:
            w.u32(self.kem_ct[0]).raw(self.kem_ct[1], CIPHERTEXT_LEN)
        if self.kem_pub:
            w.u32(self.kem_pub[0]).key(ALG_MLKEM768, self.kem_pub[1])
        return w.getvalue()

    @classmethod
    def read(cls, r: Reader) -> Header:
        if r.u8() != PROTOCOL_VERSION:
            raise ParseError("unsupported protocol version")
        flags = r.u8()
        if flags & ~(FLAG_KEM_CT | FLAG_KEM_PUB):
            raise ParseError("unknown header flags")
        dh = r.key(ALG_X25519)
        pn, n, ack = r.u32(), r.u32(), r.u32()
        ct = (r.u32(), r.raw(CIPHERTEXT_LEN)) if flags & FLAG_KEM_CT else None
        pub = (r.u32(), r.key(ALG_MLKEM768)) if flags & FLAG_KEM_PUB else None
        return cls(dh, pn, n, ack, ct, pub)


def parse_message(message: bytes) -> tuple[Header, bytes, bytes]:
    r = Reader(message, MAX_MESSAGE)
    header = Header.read(r)
    header_bytes = r.consumed()
    body = r.var(MAX_PLAINTEXT + aead.TAG_LEN + 1)  # > 0xFFFF, so a u32 length prefix
    r.end()
    return header, header_bytes, body


# ------------------------------------------------------------------------------ KDFs
def kdf_rk(
    rk: bytes | bytearray, dh_out: bytearray, ss: bytearray | None
) -> tuple[bytearray, bytearray]:
    ikm = bytearray(dh_out) + (ss if ss is not None else b"")
    info = labels.RATCHET_ROOT_PQ if ss is not None else labels.RATCHET_ROOT
    okm = kdf.hkdf(ikm, bytes(rk), info, 64)
    new_rk, ck = bytearray(okm[:32]), bytearray(okm[32:])
    wipe(ikm, okm, dh_out, ss)
    return new_rk, ck


def kdf_ck(ck: bytes | bytearray) -> tuple[bytearray, bytearray]:
    """Returns (next chain key, message key)."""
    return kdf.hmac_sha256(ck, labels.RATCHET_CHAIN_NEXT), kdf.hmac_sha256(
        ck, labels.RATCHET_CHAIN_MSG
    )


def message_keys(mk: bytes | bytearray) -> tuple[bytearray, bytes]:
    okm = kdf.hkdf(mk, ZERO_SALT, labels.RATCHET_MSG_KEYS, aead.KEY_LEN + aead.NONCE_LEN)
    key, nonce = bytearray(okm[: aead.KEY_LEN]), bytes(okm[aead.KEY_LEN :])
    wipe(okm)
    return key, nonce


# ------------------------------------------------------------------------------ state
@dataclass
class RatchetState:
    rk: bytearray
    dhs: X25519KeyPair
    dhr: bytes | None
    cks: bytearray | None
    ckr: bytearray | None
    ad: bytes
    kem: KemRatchet
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: dict[tuple[bytes, int], bytearray] = field(default_factory=dict)
    pending_ct: tuple[int, bytes] | None = None
    dh_factory: DhFactory = field(default=X25519KeyPair.generate)

    def clone(self) -> RatchetState:
        return RatchetState(
            rk=bytearray(self.rk),
            dhs=self.dhs,
            dhr=self.dhr,
            cks=bytearray(self.cks) if self.cks is not None else None,
            ckr=bytearray(self.ckr) if self.ckr is not None else None,
            ad=self.ad,
            kem=self.kem.clone(),
            ns=self.ns,
            nr=self.nr,
            pn=self.pn,
            skipped={k: bytearray(v) for k, v in self.skipped.items()},
            pending_ct=self.pending_ct,
            dh_factory=self.dh_factory,
        )


class Ratchet:
    """One side of a session. ``encrypt`` / ``decrypt`` are the only public operations."""

    def __init__(self, state: RatchetState) -> None:
        self.state = state

    # ---------------------------------------------------------------- construction
    @classmethod
    def init_alice(
        cls,
        root_key: bytearray,
        ad: bytes,
        bob_ratchet_public: bytes,
        *,
        interval: int = 4,
        dh_factory: DhFactory | None = None,
        kem: KemRatchet | None = None,
    ) -> Ratchet:
        dh_factory = dh_factory or X25519KeyPair.generate
        st = RatchetState(
            rk=bytearray(root_key),
            dhs=dh_factory(),
            dhr=bytes(bob_ratchet_public),
            cks=None,
            ckr=None,
            ad=ad,
            kem=kem or KemRatchet.create(interval),
            dh_factory=dh_factory,
        )
        _new_sending_chain(st, generate=False)
        return cls(st)

    @classmethod
    def init_bob(
        cls,
        root_key: bytearray,
        ad: bytes,
        own_ratchet_keypair: X25519KeyPair,
        *,
        interval: int = 4,
        dh_factory: DhFactory | None = None,
        kem: KemRatchet | None = None,
    ) -> Ratchet:
        st = RatchetState(
            rk=bytearray(root_key),
            dhs=own_ratchet_keypair,
            dhr=None,
            cks=None,
            ckr=None,
            ad=ad,
            kem=kem or KemRatchet.create(interval),
            dh_factory=dh_factory or X25519KeyPair.generate,
        )
        return cls(st)

    # ---------------------------------------------------------------- send
    def encrypt(self, plaintext: bytes) -> bytes:
        st = self.state
        if st.cks is None:
            raise ProtocolError("cannot send before the first message from the peer")
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError("message too long")
        st.cks, mk = kdf_ck(st.cks)
        header = Header(
            dh=st.dhs.public,
            pn=st.pn,
            n=st.ns,
            kem_ack=st.kem.peer_ack,
            kem_ct=st.pending_ct,
            kem_pub=st.kem.announcement(),
        )
        st.ns += 1
        header_bytes = header.encode()
        key, nonce = message_keys(mk)
        try:
            body = aead.seal(key, nonce, plaintext, st.ad + header_bytes)
        finally:
            wipe(key, mk)
        w = (
            Writer()
            .raw(header_bytes, len(header_bytes))
            .var(body, MAX_PLAINTEXT + aead.TAG_LEN + 1)
        )
        return w.getvalue()

    # ---------------------------------------------------------------- receive
    def decrypt(self, message: bytes) -> bytes:
        header, header_bytes, body = parse_message(message)  # strict parsing first
        st = self.state.clone()  # work on a copy; commit only if the AEAD verifies
        try:
            mk = _message_key_for(st, header)
            key, nonce = message_keys(mk)
            try:
                plaintext = aead.open_(key, nonce, body, st.ad + header_bytes)
            finally:
                wipe(key, mk)
        except CryptoError:
            raise VerificationError("message failed authentication") from None
        st.kem.on_authenticated_header(header.kem_ack, header.kem_pub)
        self.state = st
        return plaintext

    @property
    def missing(self) -> int:
        """Messages the peer sent that have not arrived yet (SR-33 gap detection)."""
        return len(self.state.skipped)


# ------------------------------------------------------------------------------ internals
def _new_sending_chain(st: RatchetState, *, generate: bool = True) -> None:
    if generate:
        st.dhs = st.dh_factory()
    if not (st.dhr is not None):
        raise ProtocolError("internal state error")
    st.pending_ct, ss = st.kem.on_new_sending_chain()
    st.rk, st.cks = kdf_rk(st.rk, st.dhs.dh(st.dhr), ss)


def _skip_until(st: RatchetState, until: int) -> None:
    if st.ckr is None:
        return
    if until - st.nr > MAX_SKIP or len(st.skipped) + max(0, until - st.nr) > MAX_SKIP:
        raise VerificationError("too many skipped messages")
    if not (st.dhr is not None):
        raise ProtocolError("internal state error")
    while st.nr < until:
        st.ckr, mk = kdf_ck(st.ckr)
        st.skipped[(st.dhr, st.nr)] = mk
        st.nr += 1


def _message_key_for(st: RatchetState, h: Header) -> bytearray:
    stored = st.skipped.pop((h.dh, h.n), None)
    if stored is not None:
        return stored
    if h.dh != st.dhr:
        _skip_until(st, h.pn)
        ss = st.kem.decapsulate(*h.kem_ct) if h.kem_ct else None
        st.pn, st.ns, st.nr = st.ns, 0, 0
        st.dhr = h.dh
        st.rk, st.ckr = kdf_rk(st.rk, st.dhs.dh(st.dhr), ss)
        _new_sending_chain(st)
    elif h.n < st.nr:
        raise ReplayError("message key already used (replay)")
    _skip_until(st, h.n)
    if not (st.ckr is not None):
        raise ProtocolError("internal state error")
    st.ckr, mk = kdf_ck(st.ckr)
    st.nr += 1
    return mk
