"""A complete end-to-end session: handshake (M3) followed by the PQ double ratchet (M5)."""

from __future__ import annotations

from pqchat.protocol import handshake
from pqchat.protocol.bundle import IdentityKeys, IdentityPublic, PrekeyBundle, PrekeyStore
from pqchat.protocol.errors import ProtocolError
from pqchat.protocol.modes import Mode, Policy
from pqchat.protocol.padding import pad, unpad
from pqchat.protocol.pq_ratchet import DEFAULT_INTERVAL, KemFactory, KemRatchet
from pqchat.protocol.ratchet import DhFactory, Ratchet
from pqchat.protocol.safety import safety_number


class Session:
    def __init__(self, ratchet: Ratchet, own: IdentityPublic, peer: IdentityPublic, mode: Mode):
        self.ratchet = ratchet
        self.own = own
        self.peer = peer
        self.mode = mode

    @classmethod
    def initiate(
        cls,
        alice: IdentityKeys,
        bundle: PrekeyBundle,
        first_plaintext: bytes,
        *,
        mode: Mode = Mode.HYBRID,
        policy: Policy | None = None,
        now: int | None = None,
        interval: int = DEFAULT_INTERVAL,
        dh_factory: DhFactory | None = None,
        kem_factory: KemFactory | None = None,
    ) -> tuple[Session, bytes]:
        made: list[Ratchet] = []

        def first_ratchet_message(init: handshake.SessionInit) -> bytes:
            # Alice's first message is a normal ratchet message (with her ratchet public key
            # and ML-KEM announcement), carried inside the handshake AEAD. Bob can therefore
            # answer immediately, exactly as in Signal.
            if init.peer_ratchet_public is None:
                raise ProtocolError("internal state error")
            ratchet = Ratchet.init_alice(
                init.root_key,
                init.associated_data,
                init.peer_ratchet_public,
                dh_factory=dh_factory,
                kem=KemRatchet.create(interval, kem_factory),
            )
            made.append(ratchet)
            return ratchet.encrypt(pad(first_plaintext))

        message, init = handshake.initiate(
            alice,
            bundle,
            b"",
            mode=mode,
            policy=policy,
            now=now,
            payload_builder=first_ratchet_message,
        )
        ratchet = made[0]
        return cls(ratchet, alice.public, init.peer, mode), message

    @classmethod
    def accept(
        cls,
        bob: PrekeyStore,
        message: bytes,
        *,
        policy: Policy | None = None,
        replay_cache: handshake.ReplayCache | None = None,
        now: int | None = None,
        interval: int = DEFAULT_INTERVAL,
        dh_factory: DhFactory | None = None,
        kem_factory: KemFactory | None = None,
    ) -> tuple[Session, bytes]:
        init = handshake.respond(bob, message, policy=policy, replay_cache=replay_cache, now=now)
        if init.own_ratchet_keypair is None:
            raise ProtocolError("internal state error")
        ratchet = Ratchet.init_bob(
            init.root_key,
            init.associated_data,
            init.own_ratchet_keypair,
            dh_factory=dh_factory,
            kem=KemRatchet.create(interval, kem_factory),
        )
        # The handshake payload is Alice's first ratchet message: process it normally.
        plaintext = unpad(ratchet.decrypt(init.plaintext))
        return cls(ratchet, bob.identity.public, init.peer, init.mode), plaintext

    def encrypt(self, plaintext: bytes) -> bytes:
        """Pad to a size bucket (SR-24), then encrypt with the next ratchet key."""
        return self.ratchet.encrypt(pad(plaintext))

    def decrypt(self, message: bytes) -> bytes:
        return unpad(self.ratchet.decrypt(message))

    @property
    def missing_messages(self) -> int:
        return self.ratchet.missing

    def safety_number(self) -> str:
        return safety_number(self.own, self.peer)
