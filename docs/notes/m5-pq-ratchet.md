# Design note — Milestone 5: double ratchet with post-quantum re-keying

**Status:** implemented without a separate approval stop (student chose "no stops, review after" on
2026-11-06). CLAUDE.md §5.3 normally requires approval of this note before coding; please review
it with extra care.

## 1. What we build, and what we do not

* **Classical part:** Signal's Double Ratchet (Perrin & Marlinspike, rev. 4, 2025): an X25519
  DH ratchet, symmetric-key chains with an HMAC-SHA256 KDF, AES-256-GCM, header with `DH`, `PN`, `N`,
  at most 1000 stored skipped message keys.
* **Post-quantum part (simplified SPQR):** periodically one side encapsulates to the other side's
  current ML-KEM-768 *ratchet* public key and mixes the shared secret into the root KDF together with
  the DH output: `(RK, CK) = HKDF(salt = RK, ikm = DH_out || SS_kem)`.

> **This is a simplification of Signal's SPQR.** Signal's Sparse Post-Quantum Ratchet (2025) uses the
> **ML-KEM Braid**: KEM keys and ciphertexts are split into chunks with erasure coding and spread over
> many messages, so per-message overhead stays small and progress survives message loss. Our design
> sends a whole ML-KEM ciphertext (1,088 B) and a whole new public key (1,184 B) in the headers of a
> re-key chain. That is simpler to implement, analyse and explain, but costs ≈ 2.3 KB on those messages.
> The thesis must state this difference.

## 2. Why a PQ ratchet at all

The handshake already mixes ML-KEM into the first root key, so a harvest-now-decrypt-later attacker
(A4) cannot decrypt *any* message of a session started with hybrid: every later key descends from RK.
The PQ ratchet is about **post-compromise security against A4**: if a device's state is stolen at
time *t* (A3), the X25519 ratchet normally heals the session after one round trip, because new DH
secrets appear. A quantum attacker can compute those DH secrets from the public keys in the headers,
so DH steps alone never heal against A4. A fresh ML-KEM secret, encapsulated to a key generated
*after* the compromise, does.

## 3. State

| Field | Meaning |
|---|---|
| `RK` | root key (32 B) |
| `DHs`, `DHr` | own ratchet key pair, peer's ratchet public key |
| `CKs`, `CKr` | sending / receiving chain keys |
| `Ns`, `Nr`, `PN` | message numbers in the current sending / receiving chain, length of previous sending chain |
| `skipped` | `(DH pub, N) → message key`, max 1000 in total |
| `KEMs` | own ML-KEM ratchet key pairs by id (current + previous, so late messages still work) |
| `KEMr` | peer's newest ML-KEM ratchet public key and its id |
| `chains_since_pq` | own sending chains since this party last mixed in a KEM secret |
| `pending_pq` | `(kem_ct, target_id, new_own_kem_pub, new_own_id)` attached to every header of the current sending chain, or none |
| `AD` | associated data from the handshake (identities and prekey binding) |

## 4. Initialisation (from the M3 handshake)

* **Alice:** `DHr = SPK_B`; `KEMr = PQSPK_B` (Bob's signed ML-KEM prekey); generate `DHs` and a first
  `KEMs`; perform a sending step (§5.2). Her first chain therefore advertises her KEM key.
* **Bob:** `DHs = SPK_B` key pair; `KEMs = {id(PQSPK_B): PQSPK_B key pair}`; waits for Alice.

## 5. Algorithms

### 5.1 KDFs (labels in `crypto/labels.py`)

```
KDF_RK(RK, dh, ss?) = HKDF(salt = RK, ikm = dh [|| ss], info = "…ratchet root" or "…ratchet root pq", 64) → RK', CK
KDF_CK(CK)          = MK = HMAC(CK, "…ratchet chain message"),  CK' = HMAC(CK, "…ratchet chain next")
message key → (enc key 32 B, nonce 12 B) = HKDF(salt = 0, ikm = MK, info = "…ratchet message keys", 44)
```

Different `info` labels for the DH-only and DH+KEM root steps mean the two can never collide.

### 5.2 Sending step (new sending chain)

Happens once after receiving a new peer DH key (and once at Alice's start):

1. Generate new `DHs`.
2. If `chains_since_pq + 1 >= K/2` and `KEMr` is known: `(CT, SS) = Encaps(KEMr)`; generate a new own
   KEM key pair `KEMs'`; `pending_pq = (CT, id(KEMr), pub(KEMs'), id(KEMs'))`; `chains_since_pq = 0`.
   Otherwise `pending_pq = none`, `chains_since_pq += 1`.
3. `RK, CKs = KDF_RK(RK, DH(DHs, DHr), SS)` (SS omitted when no PQ step).

`K` counts DH ratchet steps of *both* parties (default 4), so each party re-keys every `K/2 = 2` of
its own sending chains: a PQ secret enters the root chain every 4 DH steps, as CLAUDE.md §5.3 asks.

### 5.3 Header

```
header = version u8 | flags u8 | key(X25519, DHs) | PN u32 | N u32 | kem_ack u32
         [| target_kem_id u32 | CT[1088]]              (flag 0x01: ML-KEM re-key)
         [| own_kem_id u32 | key(MLKEM768, public)]    (flag 0x02: KEM key announcement)
```

*Change made while implementing:* `kem_ack` (4 B) carries the newest peer KEM key id the sender has
seen. Without it a party cannot know whether its announced public key arrived, and would have to
repeat 1,185 B in every message. A key is announced until the peer acknowledges it.

Every message of a re-key chain repeats the ciphertext, so it arrives even if earlier messages are
lost or reordered. Measured sizes: plain header 47 B; with ciphertext 1,139 B; with ciphertext and a
new public key 2,328 B.

### 5.4 Receiving

On a message with header `h`:

1. Strict parse (version, flags, lengths, no trailing bytes) before anything else.
2. If `(h.DH, h.N)` is in `skipped`: decrypt with that key, delete it, done.
3. If `h.DH != DHr` (new chain from the peer):
   * store skipped keys of the current receiving chain up to `h.PN` (limit 1000);
   * if `h` has a PQ part: `SS = Decaps(KEMs[target_kem_id], CT)`; remember `KEMr = (own_kem_id, KEMs')`;
   * `RK, CKr = KDF_RK(RK, DH(DHs, h.DH), SS)`, `DHr = h.DH`, `Nr = 0`;
   * sending step (§5.2) for our next chain.
4. Store skipped keys up to `h.N`; derive the message key; decrypt with `AD || header`.
5. **All of this runs on a copy of the state, which replaces the real state only if the AEAD
   succeeds.** A forged or corrupted message therefore cannot desynchronise or poison the session.

A message number already passed (and not in `skipped`) is a replay and is rejected (SR-12). Old own
KEM key pairs are deleted once the peer has used a newer one (keep current + one previous).

## 6. Results (see tests)

Healing measured in `tests/unit/test_ratchet_pcs.py` (rounds after the theft in which the attacker
can still read Alice's messages):

| K | classical attacker | quantum attacker (all X25519 keys known) |
|---|---|---|
| 4 | 2 | 2 |
| 8 | 2 | 4 |
| 12 | 2 | 6 |

The first two rounds are readable even classically, because Bob's next sending key was created
*before* the theft. Against a quantum attacker only the ML-KEM step heals, after K/2 rounds; with the
default K = 4 that coincides with classical healing.

## 7. Tests ("done when": out-of-order, forward-secrecy and post-compromise-security tests pass)

| Property | Test |
|---|---|
| `decrypt(encrypt(m)) == m`; out-of-order and dropped messages | `tests/property/test_ratchet_out_of_order.py` (Hypothesis permutations) |
| Replays rejected; skipped-key limit | `tests/negative/test_replay.py::test_ratchet_replay`, `tests/negative/test_ratchet_limits.py` |
| Bit flip in header or ciphertext rejected, state unchanged | `tests/property/test_ratchet_bitflip.py` |
| Forward secrecy | `tests/unit/test_ratchet_fs.py` |
| Classical PCS: attacker with a state copy loses access after one round trip | `tests/unit/test_ratchet_pcs.py` |
| **PQ PCS:** attacker with a state copy **and all X25519 private keys** (quantum) keeps access until the next ML-KEM step, then loses it | `tests/unit/test_ratchet_pcs.py` |
| Gap detection | `tests/unit/test_ratchet_gap.py` |
| PQ step frequency (K = 4) | `tests/unit/test_ratchet.py` |

The PQ PCS test models the quantum attacker by giving a "shadow" copy of Bob's state the *actual* DH
key pairs Bob generates later (as if computed from the public keys), but fresh, unrelated ML-KEM keys.

## 8. Bounded formal model

`formal/ratchet_bounded.pv` models two PQ-ratchet steps after a full state compromise with X25519
broken, and checks that a message sent after the KEM step stays secret, while one sent before it
does not (expected attack). Bounded because ProVerif cannot verify unbounded ratchets with
compromise in reasonable time.
