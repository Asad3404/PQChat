"""The post-quantum half of the ratchet: ML-KEM-768 re-keying (simplified SPQR).

See docs/notes/m5-pq-ratchet.md. Each party keeps its own current ML-KEM ratchet key pair
(plus the previous one, for late messages), announces the public key in its headers until the
peer acknowledges it, and every ``interval / 2`` of its own sending chains encapsulates to the
peer's newest key. The shared secret is mixed into the root KDF together with the DH output.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field

from pqchat.crypto.kem import MLKEMKeyPair, encapsulate
from pqchat.protocol.errors import VerificationError

KemFactory = Callable[[], MLKEMKeyPair]
DEFAULT_INTERVAL = 4  # K: DH ratchet steps (both parties together) between ML-KEM steps


def _new_id(taken: set[int]) -> int:
    while True:
        key_id = int.from_bytes(os.urandom(4), "big")
        if key_id and key_id not in taken:
            return key_id


@dataclass
class KemRatchet:
    interval: int
    own: dict[int, MLKEMKeyPair]
    current_id: int
    previous_id: int | None = None
    #: Announce our current public key in headers until the peer acknowledges it.
    announce: bool = True
    #: Peer's newest announced key (id, public key).
    peer: tuple[int, bytes] | None = None
    #: Newest peer key id we have *seen*; sent back as an acknowledgement.
    peer_ack: int = 0
    chains_since: int = 0
    factory: KemFactory = field(default=MLKEMKeyPair.generate)

    @classmethod
    def create(
        cls, interval: int = DEFAULT_INTERVAL, factory: KemFactory | None = None
    ) -> KemRatchet:
        if interval < 2 or interval % 2:
            raise ValueError("PQ re-key interval K must be an even number >= 2")
        factory = factory or MLKEMKeyPair.generate
        key_id = _new_id(set())
        return cls(interval=interval, own={key_id: factory()}, current_id=key_id, factory=factory)

    def clone(self) -> KemRatchet:
        return KemRatchet(
            interval=self.interval,
            own=dict(self.own),
            current_id=self.current_id,
            previous_id=self.previous_id,
            announce=self.announce,
            peer=self.peer,
            peer_ack=self.peer_ack,
            chains_since=self.chains_since,
            factory=self.factory,
        )

    # ---------------------------------------------------------------- sending side
    def on_new_sending_chain(self) -> tuple[tuple[int, bytes] | None, bytearray | None]:
        """Called once per new own sending chain. Returns ((target_id, CT) or None, SS or None)."""
        self.chains_since += 1
        if self.peer is None or self.chains_since < self.interval // 2:
            return None, None
        self.chains_since = 0
        target_id, public = self.peer
        ct, ss = encapsulate(public)
        return (target_id, ct), ss

    def announcement(self) -> tuple[int, bytes] | None:
        if not self.announce:
            return None
        return self.current_id, self.own[self.current_id].public

    # ---------------------------------------------------------------- receiving side
    def decapsulate(self, target_id: int, ct: bytes) -> bytearray:
        """Decapsulate a re-key ciphertext; rotate our key if the peer used the current one."""
        keypair = self.own.get(target_id)
        if keypair is None:
            raise VerificationError("re-key ciphertext for an unknown ML-KEM ratchet key")
        ss = keypair.decapsulate(ct)
        if target_id == self.current_id:
            # Used once: create a fresh key so the *next* re-key heals a new compromise.
            stale = self.previous_id
            self.previous_id = self.current_id
            self.current_id = _new_id(set(self.own))
            self.own[self.current_id] = self.factory()
            self.announce = True
            if stale is not None and stale in self.own:
                del self.own[stale]
        return ss

    def on_authenticated_header(self, ack_id: int, announced: tuple[int, bytes] | None) -> None:
        """Process the KEM fields of a header whose AEAD tag already verified."""
        if ack_id == self.current_id:
            self.announce = False
        if announced is not None and (self.peer is None or self.peer[0] != announced[0]):
            self.peer = announced
            self.peer_ack = announced[0]
