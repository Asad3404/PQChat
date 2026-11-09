"""Explicit JSON (de)serialisation of client state. No pickle (PROJECT-BRIEF.md §3.6).

The resulting document contains private keys and plaintext history, so it is only ever written
to disk encrypted (``pqchat.crypto.keystore_crypto``). AEAD guarantees integrity, so decoding
here only has to be type-safe, not adversarial; every field is still checked for its type.
"""

from __future__ import annotations

from typing import Any

from pqchat.crypto.dh import X25519KeyPair
from pqchat.crypto.kem import MLKEMKeyPair
from pqchat.crypto.sig import HybridSigningKey
from pqchat.protocol.bundle import IdentityKeys, IdentityPublic, PrekeyStore, decode_prekey
from pqchat.protocol.handshake import ReplayCache
from pqchat.protocol.modes import Mode
from pqchat.protocol.pq_ratchet import KemRatchet
from pqchat.protocol.ratchet import Ratchet, RatchetState
from pqchat.protocol.session import Session
from pqchat.wire import b64d, b64e

_MAX = 1 << 20


def _b(text: Any) -> bytes:
    if not isinstance(text, str):
        raise ValueError("expected base64url string")
    return b64d(text, _MAX)


def _int(v: Any) -> int:
    if type(v) is not int:
        raise ValueError("expected integer")
    return v


# ------------------------------------------------------------------------------ identity
def identity_to(ident: IdentityKeys) -> dict[str, Any]:
    ed, pq = ident.signing.private_parts()
    return {
        "ed": b64e(bytes(ed)),
        "pq_pub": b64e(ident.signing.public.mldsa65),
        "pq_sec": b64e(bytes(pq)),
        "dh": b64e(bytes(ident.dh.private_bytes())),
    }


def identity_from(d: dict[str, Any]) -> IdentityKeys:
    signing = HybridSigningKey(_b(d["ed"]), _b(d["pq_pub"]), _b(d["pq_sec"]))
    return IdentityKeys(signing, X25519KeyPair.from_private_bytes(_b(d["dh"])))


# ------------------------------------------------------------------------------ prekeys
def prekeys_to(store: PrekeyStore) -> dict[str, Any]:
    def dh_list(table: dict[int, Any]) -> list[list[Any]]:
        return [
            [k, b64e(bytes(kp.private_bytes())), b64e(pk.encode())] for k, (kp, pk) in table.items()
        ]

    def kem_list(table: dict[int, Any]) -> list[list[Any]]:
        return [
            [k, b64e(kp.public), b64e(bytes(kp.secret_bytes())), b64e(pk.encode())]
            for k, (kp, pk) in table.items()
        ]

    return {
        "signed_dh": dh_list(store.signed_dh),
        "signed_kem": kem_list(store.signed_kem),
        "one_time_dh": dh_list(store.one_time_dh),
        "one_time_kem": kem_list(store.one_time_kem),
    }


def prekeys_from(identity: IdentityKeys, d: dict[str, Any]) -> PrekeyStore:
    store = PrekeyStore(identity)
    for k, priv, blob in d["signed_dh"]:
        store.signed_dh[_int(k)] = (
            X25519KeyPair.from_private_bytes(_b(priv)),
            decode_prekey(_b(blob)),
        )
    for k, priv, blob in d["one_time_dh"]:
        store.one_time_dh[_int(k)] = (
            X25519KeyPair.from_private_bytes(_b(priv)),
            decode_prekey(_b(blob)),
        )
    for k, pub, sec, blob in d["signed_kem"]:
        store.signed_kem[_int(k)] = (MLKEMKeyPair(_b(pub), _b(sec)), decode_prekey(_b(blob)))
    for k, pub, sec, blob in d["one_time_kem"]:
        store.one_time_kem[_int(k)] = (MLKEMKeyPair(_b(pub), _b(sec)), decode_prekey(_b(blob)))
    return store


# ------------------------------------------------------------------------------ sessions
def _opt(v: bytes | bytearray | None) -> str | None:
    return None if v is None else b64e(bytes(v))


def _opt_from(v: Any) -> bytes | None:
    return None if v is None else _b(v)


def session_to(s: Session) -> dict[str, Any]:
    st = s.ratchet.state
    k = st.kem
    return {
        "mode": int(s.mode),
        "peer": b64e(s.peer.encode()),
        "rk": b64e(bytes(st.rk)),
        "dhs": b64e(bytes(st.dhs.private_bytes())),
        "dhr": _opt(st.dhr),
        "cks": _opt(st.cks),
        "ckr": _opt(st.ckr),
        "ad": b64e(st.ad),
        "ns": st.ns,
        "nr": st.nr,
        "pn": st.pn,
        "skipped": [[b64e(dh), n, b64e(bytes(mk))] for (dh, n), mk in st.skipped.items()],
        "pending_ct": None if st.pending_ct is None else [st.pending_ct[0], b64e(st.pending_ct[1])],
        "kem": {
            "interval": k.interval,
            "own": [
                [i, b64e(kp.public), b64e(bytes(kp.secret_bytes()))] for i, kp in k.own.items()
            ],
            "current_id": k.current_id,
            "previous_id": k.previous_id,
            "announce": k.announce,
            "peer": None if k.peer is None else [k.peer[0], b64e(k.peer[1])],
            "peer_ack": k.peer_ack,
            "chains_since": k.chains_since,
        },
    }


def session_from(own: IdentityPublic, d: dict[str, Any]) -> Session:
    kd = d["kem"]
    kem = KemRatchet(
        interval=_int(kd["interval"]),
        own={_int(i): MLKEMKeyPair(_b(p), _b(s)) for i, p, s in kd["own"]},
        current_id=_int(kd["current_id"]),
        previous_id=None if kd["previous_id"] is None else _int(kd["previous_id"]),
        announce=bool(kd["announce"]),
        peer=None if kd["peer"] is None else (_int(kd["peer"][0]), _b(kd["peer"][1])),
        peer_ack=_int(kd["peer_ack"]),
        chains_since=_int(kd["chains_since"]),
    )
    cks, ckr = _opt_from(d["cks"]), _opt_from(d["ckr"])
    state = RatchetState(
        rk=bytearray(_b(d["rk"])),
        dhs=X25519KeyPair.from_private_bytes(_b(d["dhs"])),
        dhr=_opt_from(d["dhr"]),
        cks=bytearray(cks) if cks is not None else None,
        ckr=bytearray(ckr) if ckr is not None else None,
        ad=_b(d["ad"]),
        kem=kem,
        ns=_int(d["ns"]),
        nr=_int(d["nr"]),
        pn=_int(d["pn"]),
        skipped={(_b(dh), _int(n)): bytearray(_b(mk)) for dh, n, mk in d["skipped"]},
        pending_ct=None
        if d["pending_ct"] is None
        else (_int(d["pending_ct"][0]), _b(d["pending_ct"][1])),
    )
    return Session(Ratchet(state), own, IdentityPublic.decode(_b(d["peer"])), Mode(_int(d["mode"])))


def replay_to(cache: ReplayCache) -> dict[str, int]:
    return {b64e(k): v for k, v in cache.seen.items()}


def replay_from(d: dict[str, Any]) -> ReplayCache:
    return ReplayCache({_b(k): _int(v) for k, v in d.items()})
