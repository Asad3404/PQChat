# ProVerif results (Milestones 4 and 5)

**Tool:** ProVerif 2.05 (`opam install proverif`). **Run:** `formal/run.sh` (all scenarios, ≈ 30 min)
or `formal/run.sh --quick` (secrecy only). Raw output of the run below: `evidence/m4/proverif-summary.txt`.
CI runs the full script and fails if any result differs from the expected column.

"true" = property **proved** for an unbounded number of sessions. "false" = ProVerif **found an attack**.
Every "false" below is *expected*: it shows either a limit of the design or that the model is not vacuous.

## Handshake (`formal/handshake.pv`)

The attacker controls the network and the relay (A1 + A2), can register its own identities, and knows
all keys of a compromised user "Charlie". Honest Alice talks to honest Bob and to Charlie; Bob uses a
fresh one-time X25519 and ML-KEM prekey per session.

| Scenario | Attacker extra power | Secrecy of Alice's message | Authentication of Alice to Bob | Time |
|---|---|---|---|---|
| hybrid | — | **true** | **true** | 180 s / 249 s |
| hybrid, forward secrecy | all identity keys leak after the session | **true** | — | 191 s |
| hybrid, harvest-now-decrypt-later | every X25519 and Ed25519 secret leaks after the session (quantum, later) | **true** | — | 190 s |
| hybrid, X25519 + Ed25519 broken from the start | active quantum attacker | **true** | **false** (attack) | 107 s / 63 s |
| hybrid, ML-KEM + ML-DSA broken from the start | flaw in the new PQ algorithms | **true** | **true** | 216 s / 515 s |
| hybrid, *everything* broken | sanity check | false (attack) | — | 27 s |
| classical | — | **true** | **true** | 1 s / 2 s |
| classical, forward secrecy | identity keys leak after the session | **true** | — | 3 s |
| classical, harvest-now-decrypt-later | X25519/Ed25519 secrets leak after the session | **false** (attack) | — | 2 s |

### What the results mean

1. **Hybrid security holds in both directions.** Secrecy survives a break of X25519 *or* of ML-KEM
   (rows 4 and 5). This is the core claim of the project, now proved.
2. **Classical mode falls to harvest-now-decrypt-later; hybrid does not** (row 9 vs. row 3). This is
   the M4 "done when" condition.
3. **Limitation found: authentication of Alice is classical.** With X25519/Ed25519 broken *during*
   the handshake, the attacker can impersonate Alice to Bob (row 4, authentication false). Reason:
   Bob authenticates Alice only through `DH1 = DH(IKdh_A, SPK_B)`; the ML-DSA signature on `IKdh_A`
   proves the key is Alice's, but not that Alice took part in *this* session. Secrecy still holds,
   because only Bob can decapsulate. Signal's PQXDH has the same property. A fix would be for Alice to
   sign the transcript with ML-DSA (as `pq-only` mode does), at the cost of deniability — recorded as
   future work. This was predicted before the model was written.
4. **Authentication query is non-injective.** The injective version did not terminate within 40 min.
   Injectivity (no replay) rests on Bob's fresh one-time prekey per session (consumed only after
   authentication, SR-10) and the replay cache (SR-11), and is tested in `tests/negative/`.

### Modelling choices and abstractions

* Perfect cryptography (symbolic / Dolev-Yao model): DH with the commutation equation, KEM and
  signatures as constructors with destructors, HKDF as a random oracle, AEAD as ideal.
* "Broken" primitives are modelled by giving the attacker a destructor that recovers the secret key
  from the public key (`dh_break`, `ed_break`, `kem_break`, `pq_break`).
* Harvest-now-decrypt-later = classical secrets released in `phase 1`, after all sessions ended.
* Not modelled: prekey expiry times and IDs, the exact byte encoding, padding, last-resort-only
  sessions (covered by tests), multiple devices.

## Ratchet (`formal/ratchet_bounded.pv`, M5)

Bounded: one compromise (root key stolen), X25519 broken (all DH outputs public), two root steps.

| Message | Sent | Expected | Result |
|---|---|---|---|
| m1 | after a DH-only step | leaks | false (attack) ✓ |
| m2c | after a second DH-only step (counterfactual) | leaks | false (attack) ✓ |
| m2 | after a step that mixes in a fresh ML-KEM secret | secret | **true** ✓ |

So against a quantum attacker **only the ML-KEM re-key heals the session**, confirming the measured
results in `tests/unit/test_ratchet_pcs.py` (a quantum attacker keeps access for K/2 round trips).
Assumption: the attacker is passive while the fresh KEM public key travels; an active attacker holding
the stolen root key could substitute it (standard limit of post-compromise security).
