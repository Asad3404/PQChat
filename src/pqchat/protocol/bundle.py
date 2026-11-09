"""Identity keys, signed prekeys and prekey bundles (PROJECT-BRIEF.md §5.1, SR-5, SR-10, SR-18).

Wire formats (see docs/protocol-spec.md §3):

    IdentityPublic = key(ED25519) key(MLDSA65) key(X25519) sig_ed[64] sig_pq[3309]
        signatures cover  SIG_IDENTITY_DH || key(ED25519) key(MLDSA65) key(X25519)

    Prekey = kind u8 | key_id u32 | key(X25519 or MLKEM768) | created_at u64 | expires_at u64
             | sig_ed[64] | sig_pq[3309]
        signatures cover  SIG_PREKEY || (everything before the signatures)

    Bundle = version u8 | IdentityPublic | flags u8 | SPK | [PQSPK] | [OPK] | [PQOPK]
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum

from pqchat.crypto import labels
from pqchat.crypto.dh import X25519KeyPair
from pqchat.crypto.kem import MLKEMKeyPair
from pqchat.crypto.sig import (
    ED_SIG_LEN,
    MLDSA_SIG_LEN,
    HybridPublicKey,
    HybridSignature,
    HybridSigningKey,
    ed25519_verify,
    mldsa_verify,
)
from pqchat.protocol.encoding import (
    ALG_ED25519,
    ALG_MLDSA65,
    ALG_MLKEM768,
    ALG_X25519,
    Reader,
    Writer,
)
from pqchat.protocol.errors import DowngradeError, ParseError, ReplayError, VerificationError
from pqchat.protocol.modes import PROTOCOL_VERSION, Mode, Policy, uses_ed25519, uses_mldsa

DAY = 86_400
#: Maximum lifetime a client accepts for a signed prekey (rotate weekly, tolerate 30 days).
MAX_SIGNED_PREKEY_LIFETIME = 30 * DAY
#: One-time prekeys may wait on the relay longer.
MAX_ONE_TIME_PREKEY_LIFETIME = 90 * DAY
DEFAULT_SIGNED_PREKEY_LIFETIME = 7 * DAY
DEFAULT_ONE_TIME_PREKEY_LIFETIME = 60 * DAY

IDENTITY_LEN = (1 + 32) + (1 + 1952) + (1 + 32) + ED_SIG_LEN + MLDSA_SIG_LEN
MAX_BUNDLE_LEN = 32 * 1024

FLAG_PQSPK = 0x01
FLAG_OPK = 0x02
FLAG_PQOPK = 0x04


class PrekeyKind(IntEnum):
    SIGNED = 1
    ONE_TIME = 2


def _check_signatures(
    mode: Mode, public: HybridPublicKey, signature: HybridSignature, label: bytes, msg: bytes
) -> bool:
    """Verify the signatures the mode requires. Hybrid needs BOTH (SR-5)."""
    results = []
    if uses_ed25519(mode):
        results.append(ed25519_verify(public.ed25519, signature.ed25519, label, msg))
    if uses_mldsa(mode):
        results.append(mldsa_verify(public.mldsa65, signature.mldsa65, label, msg))
    return all(results)


# ------------------------------------------------------------------------------ identity
@dataclass(frozen=True)
class IdentityPublic:
    sign: HybridPublicKey
    dh: bytes
    dh_signature: HybridSignature

    def signed_part(self) -> bytes:
        return (
            Writer()
            .key(ALG_ED25519, self.sign.ed25519)
            .key(ALG_MLDSA65, self.sign.mldsa65)
            .key(ALG_X25519, self.dh)
            .getvalue()
        )

    def encode(self) -> bytes:
        w = Writer()
        w.raw(self.signed_part(), IDENTITY_LEN - ED_SIG_LEN - MLDSA_SIG_LEN)
        w.raw(self.dh_signature.ed25519, ED_SIG_LEN)
        w.raw(self.dh_signature.mldsa65, MLDSA_SIG_LEN)
        return w.getvalue()

    @classmethod
    def read(cls, r: Reader) -> IdentityPublic:
        ed = r.key(ALG_ED25519)
        pq = r.key(ALG_MLDSA65)
        dh = r.key(ALG_X25519)
        sig = HybridSignature(r.raw(ED_SIG_LEN), r.raw(MLDSA_SIG_LEN))
        return cls(HybridPublicKey(ed, pq), dh, sig)

    @classmethod
    def decode(cls, data: bytes) -> IdentityPublic:
        r = Reader(data, IDENTITY_LEN)
        ident = cls.read(r)
        r.end()
        return ident

    def verify(self, mode: Mode) -> None:
        if not _check_signatures(
            mode, self.sign, self.dh_signature, labels.SIG_IDENTITY_DH, self.signed_part()
        ):
            raise VerificationError("identity key signature invalid")


class IdentityKeys:
    """A user's long-term private identity: IKsig-ed, IKsig-pq and IKdh."""

    __slots__ = ("dh", "public", "signing")

    def __init__(self, signing: HybridSigningKey, dh: X25519KeyPair) -> None:
        self.signing = signing
        self.dh = dh
        unsigned = IdentityPublic(signing.public, dh.public, HybridSignature(b"", b""))
        sig = signing.sign(labels.SIG_IDENTITY_DH, unsigned.signed_part())
        self.public = IdentityPublic(signing.public, dh.public, sig)

    @classmethod
    def generate(cls) -> IdentityKeys:
        return cls(HybridSigningKey.generate(), X25519KeyPair.generate())


# ------------------------------------------------------------------------------ prekeys
@dataclass(frozen=True)
class SignedPrekey:
    kind: PrekeyKind
    key_id: int
    alg: int
    public: bytes
    created_at: int
    expires_at: int
    signature: HybridSignature

    def signed_part(self) -> bytes:
        return (
            Writer()
            .u8(self.kind)
            .u32(self.key_id)
            .key(self.alg, self.public)
            .u64(self.created_at)
            .u64(self.expires_at)
            .getvalue()
        )

    def encode(self) -> bytes:
        return (
            Writer()
            .raw(self.signed_part(), len(self.signed_part()))
            .raw(self.signature.ed25519, ED_SIG_LEN)
            .raw(self.signature.mldsa65, MLDSA_SIG_LEN)
            .getvalue()
        )

    @classmethod
    def read(cls, r: Reader, kind: PrekeyKind, alg: int) -> SignedPrekey:
        if r.u8() != kind:
            raise ParseError("unexpected prekey kind")
        key_id = r.u32()
        public = r.key(alg)
        created, expires = r.u64(), r.u64()
        sig = HybridSignature(r.raw(ED_SIG_LEN), r.raw(MLDSA_SIG_LEN))
        return cls(kind, key_id, alg, public, created, expires, sig)

    def verify(self, owner: IdentityPublic, mode: Mode, now: int, policy: Policy) -> None:
        if not _check_signatures(
            mode, owner.sign, self.signature, labels.SIG_PREKEY, self.signed_part()
        ):
            raise VerificationError("prekey signature invalid")
        max_life = (
            MAX_SIGNED_PREKEY_LIFETIME
            if self.kind is PrekeyKind.SIGNED
            else MAX_ONE_TIME_PREKEY_LIFETIME
        )
        if self.created_at > now + policy.max_clock_skew:
            raise VerificationError("prekey created in the future")
        if now >= self.expires_at:
            raise VerificationError("prekey expired")
        if self.expires_at - self.created_at > max_life or self.expires_at <= self.created_at:
            raise VerificationError("prekey lifetime not allowed")


def sign_prekey(
    identity: IdentityKeys,
    kind: PrekeyKind,
    key_id: int,
    alg: int,
    public: bytes,
    created_at: int,
    lifetime: int,
) -> SignedPrekey:
    unsigned = SignedPrekey(
        kind, key_id, alg, public, created_at, created_at + lifetime, HybridSignature(b"", b"")
    )
    sig = identity.signing.sign(labels.SIG_PREKEY, unsigned.signed_part())
    return SignedPrekey(kind, key_id, alg, public, created_at, created_at + lifetime, sig)


# ------------------------------------------------------------------------------ bundle
@dataclass(frozen=True)
class PrekeyBundle:
    identity: IdentityPublic
    spk: SignedPrekey
    pqspk: SignedPrekey | None = None
    opk: SignedPrekey | None = None
    pqopk: SignedPrekey | None = None

    def encode(self) -> bytes:
        flags = (
            (FLAG_PQSPK if self.pqspk else 0)
            | (FLAG_OPK if self.opk else 0)
            | (FLAG_PQOPK if self.pqopk else 0)
        )
        out = bytearray()
        out += Writer().u8(PROTOCOL_VERSION).getvalue()
        out += self.identity.encode()
        out += Writer().u8(flags).getvalue()
        for pk in (self.spk, self.pqspk, self.opk, self.pqopk):
            if pk is not None:
                out += pk.encode()
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> PrekeyBundle:
        r = Reader(data, MAX_BUNDLE_LEN)
        if r.u8() != PROTOCOL_VERSION:
            raise ParseError("unsupported protocol version")
        identity = IdentityPublic.read(r)
        flags = r.u8()
        if flags & ~(FLAG_PQSPK | FLAG_OPK | FLAG_PQOPK):
            raise ParseError("unknown bundle flags")
        spk = SignedPrekey.read(r, PrekeyKind.SIGNED, ALG_X25519)
        pqspk = (
            SignedPrekey.read(r, PrekeyKind.SIGNED, ALG_MLKEM768) if flags & FLAG_PQSPK else None
        )
        opk = SignedPrekey.read(r, PrekeyKind.ONE_TIME, ALG_X25519) if flags & FLAG_OPK else None
        pqopk = (
            SignedPrekey.read(r, PrekeyKind.ONE_TIME, ALG_MLKEM768) if flags & FLAG_PQOPK else None
        )
        r.end()
        return cls(identity, spk, pqspk, opk, pqopk)

    def verify(self, mode: Mode, now: int, policy: Policy) -> None:
        """Check every signature and expiry; refuse a bundle too weak for ``mode`` (SR-6)."""
        if not policy.allowed(mode):
            raise DowngradeError("mode not allowed by local policy")
        self.identity.verify(mode)
        for pk in (self.spk, self.pqspk, self.opk, self.pqopk):
            if pk is not None:
                pk.verify(self.identity, mode, now, policy)
        if mode is not Mode.CLASSICAL and self.pqspk is None and self.pqopk is None:
            raise DowngradeError("bundle has no post-quantum prekey")

    def pq_prekey(self) -> SignedPrekey | None:
        """The KEM key to encapsulate to: one-time if available, otherwise last-resort."""
        return self.pqopk or self.pqspk


# ------------------------------------------------------------------------------ Bob's store
@dataclass
class PrekeyStore:
    """The private halves of a user's prekeys. One-time keys are removed when used (SR-10)."""

    identity: IdentityKeys
    signed_dh: dict[int, tuple[X25519KeyPair, SignedPrekey]] = field(default_factory=dict)
    signed_kem: dict[int, tuple[MLKEMKeyPair, SignedPrekey]] = field(default_factory=dict)
    one_time_dh: dict[int, tuple[X25519KeyPair, SignedPrekey]] = field(default_factory=dict)
    one_time_kem: dict[int, tuple[MLKEMKeyPair, SignedPrekey]] = field(default_factory=dict)

    @staticmethod
    def _new_id(existing: dict[int, object]) -> int:
        while True:
            key_id = int.from_bytes(os.urandom(4), "big")
            if key_id not in existing:
                return key_id

    def rotate_signed(self, now: int, lifetime: int = DEFAULT_SIGNED_PREKEY_LIFETIME) -> None:
        dh = X25519KeyPair.generate()
        dh_id = self._new_id(dict(self.signed_dh))
        self.signed_dh[dh_id] = (
            dh,
            sign_prekey(
                self.identity, PrekeyKind.SIGNED, dh_id, ALG_X25519, dh.public, now, lifetime
            ),
        )
        kem = MLKEMKeyPair.generate()
        kem_id = self._new_id(dict(self.signed_kem))
        self.signed_kem[kem_id] = (
            kem,
            sign_prekey(
                self.identity, PrekeyKind.SIGNED, kem_id, ALG_MLKEM768, kem.public, now, lifetime
            ),
        )

    def add_one_time(
        self, count: int, now: int, lifetime: int = DEFAULT_ONE_TIME_PREKEY_LIFETIME
    ) -> None:
        for _ in range(count):
            dh = X25519KeyPair.generate()
            dh_id = self._new_id(dict(self.one_time_dh))
            self.one_time_dh[dh_id] = (
                dh,
                sign_prekey(
                    self.identity, PrekeyKind.ONE_TIME, dh_id, ALG_X25519, dh.public, now, lifetime
                ),
            )
            kem = MLKEMKeyPair.generate()
            kem_id = self._new_id(dict(self.one_time_kem))
            self.one_time_kem[kem_id] = (
                kem,
                sign_prekey(
                    self.identity,
                    PrekeyKind.ONE_TIME,
                    kem_id,
                    ALG_MLKEM768,
                    kem.public,
                    now,
                    lifetime,
                ),
            )

    def current_signed(self) -> tuple[SignedPrekey, SignedPrekey]:
        """Newest signed X25519 and ML-KEM prekeys."""
        dh = max((pk for _, pk in self.signed_dh.values()), key=lambda p: p.created_at)
        kem = max((pk for _, pk in self.signed_kem.values()), key=lambda p: p.created_at)
        return dh, kem

    def bundle(self, *, with_one_time: bool = True) -> PrekeyBundle:
        """A bundle as the relay would hand it out (for tests and local use)."""
        spk, pqspk = self.current_signed()
        opk = (
            next(iter(self.one_time_dh.values()))[1] if with_one_time and self.one_time_dh else None
        )
        pqopk = (
            next(iter(self.one_time_kem.values()))[1]
            if with_one_time and self.one_time_kem
            else None
        )
        return PrekeyBundle(self.identity.public, spk, pqspk, opk, pqopk)

    def drop_expired(self, now: int) -> None:
        for store in (self.signed_dh, self.signed_kem, self.one_time_dh, self.one_time_kem):
            for key_id in [k for k, (_, pk) in store.items() if now >= pk.expires_at]:
                del store[key_id]

    # -- lookups used by the responder -------------------------------------------------
    def signed_dh_key(self, key_id: int) -> X25519KeyPair:
        try:
            return self.signed_dh[key_id][0]
        except KeyError:
            raise VerificationError("unknown signed prekey") from None

    def one_time_dh_key(self, key_id: int) -> X25519KeyPair:
        """Look up (not remove) a one-time prekey; removal happens only after the message
        authenticates, so forged messages cannot burn one-time prekeys."""
        try:
            return self.one_time_dh[key_id][0]
        except KeyError:
            raise ReplayError("one-time prekey unknown or already used") from None

    def kem_key(self, key_id: int, one_time: bool) -> MLKEMKeyPair:
        store = self.one_time_kem if one_time else self.signed_kem
        try:
            return store[key_id][0]
        except KeyError:
            if one_time:
                raise ReplayError("one-time prekey unknown or already used") from None
            raise VerificationError("unknown signed prekey") from None

    def public_record(self, key_id: int, alg: int, one_time: bool) -> SignedPrekey:
        if alg == ALG_X25519:
            return (self.one_time_dh if one_time else self.signed_dh)[key_id][1]
        return (self.one_time_kem if one_time else self.signed_kem)[key_id][1]

    def consume_one_time(self, dh_id: int | None, kem_id: int | None) -> None:
        """Delete used one-time prekeys and wipe their private keys (SR-10)."""
        if dh_id is not None:
            self.one_time_dh.pop(dh_id)
        if kem_id is not None:
            kem, _ = self.one_time_kem.pop(kem_id)
            kem.wipe()
