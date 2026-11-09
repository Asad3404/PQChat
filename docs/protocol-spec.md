# PQ-Chat protocol specification, version 1

**Status:** implemented in `src/pqchat/protocol/` (M3 handshake, M5 ratchet). Code and this document
must agree; tests in `tests/` are the executable form of every "MUST" below.

Notation: `||` concatenation; `u8/u16/u32/u64` big-endian unsigned integers; `key(A, k)` = one
algorithm-ID byte `A` followed by key `k` of the exact length for `A`; `0^n` = n zero bytes.

---

## 1. Primitives and why each was chosen

| Role | Primitive | Library | Reason |
|---|---|---|---|
| Classical key agreement | X25519 (RFC 7748) | pyca/cryptography | Fast, safe-by-default curve; the same choice as Signal, so results are comparable. |
| Post-quantum key encapsulation | ML-KEM-768 (FIPS 203) | liboqs | NIST standard, security category 3 (≈ AES-192), the level Signal's PQXDH and most hybrid TLS deployments use. |
| Classical signatures | Ed25519 (RFC 8032) | pyca/cryptography | Deterministic, no per-signature randomness to get wrong. |
| Post-quantum signatures | ML-DSA-65 (FIPS 204) | liboqs | NIST standard, category 3, matches ML-KEM-768. FIPS 204 context strings give domain separation. |
| KDF / MAC | HKDF-SHA256 (RFC 5869), HMAC-SHA256 | pyca/cryptography | Standard extract-then-expand KDF; SHA-256 keeps 128-bit security against Grover. |
| AEAD | AES-256-GCM | pyca/cryptography | Hardware-accelerated, 256-bit key keeps 128-bit post-quantum security. |
| Passphrase KDF | Argon2id (RFC 9106) | argon2-cffi | Memory-hard: makes offline guessing of a stolen key store expensive on GPUs. |

**Hybrid principle.** Secrets from X25519 and ML-KEM are both fed into one HKDF. An attacker must break
**both** to learn the session key: X25519 protects against a flaw in the young ML-KEM, ML-KEM
protects against a future quantum computer. Signatures follow the same rule (both must verify).

## 2. Identifiers

| Name | Value | | Name | Value |
|---|---|---|---|---|
| protocol version | `0x01` | | `ALG_X25519` | `0x01` (32-byte key) |
| mode `classical` | `0x01` | | `ALG_ED25519` | `0x02` (32-byte key) |
| mode `hybrid` | `0x02` | | `ALG_MLKEM768` | `0x03` (1184-byte key) |
| mode `pq-only` | `0x03` | | `ALG_MLDSA65` | `0x04` (1952-byte key) |

Suite bytes `(kex, sig, aead)` are fixed per mode: classical `(1,1,1)`, hybrid `(2,2,1)`,
pq-only `(3,3,1)`. A receiver MUST reject a suite that does not match the mode.

All labels (HKDF `info`, signature labels, binding labels) are listed in
`src/pqchat/crypto/labels.py`; each starts with `PQChat-v1` and is used for exactly one purpose.

## 3. Keys and bundles

### 3.1 Identity

```
IdentityPublic = key(ED25519, IKsig_ed) || key(MLDSA65, IKsig_pq) || key(X25519, IKdh)
                 || sig_ed[64] || sig_pq[3309]                                   (5,392 bytes)
signed data    = "PQChat-v1 sig identity-dh" || key(ED25519,…) || key(MLDSA65,…) || key(X25519,…)
```

Both signatures cover all three public keys, so a relay cannot combine keys of different users.
ML-DSA is called with the label as FIPS 204 context string.

### 3.2 Signed prekeys (incl. SR-18 expiry)

```
Prekey = kind u8 (1 signed, 2 one-time) || key_id u32 || key(X25519 | MLKEM768, pub)
         || created_at u64 || expires_at u64 || sig_ed[64] || sig_pq[3309]
signed data = "PQChat-v1 sig prekey" || everything before the signatures
```

A receiver MUST reject a prekey if: a required signature fails; `created_at > now + 300 s`;
`now >= expires_at`; `expires_at <= created_at`; or the lifetime exceeds 30 days (signed) / 90 days
(one-time). Defaults: signed prekeys 7 days, one-time 60 days.

### 3.3 Bundle

```
Bundle = version u8 || IdentityPublic || flags u8 || SPK || [PQSPK] || [OPK] || [PQOPK]
flags  = 0x01 PQSPK present | 0x02 OPK present | 0x04 PQOPK present  (other bits MUST be 0)
```

Sizes: full bundle 21,406 bytes; without one-time prekeys 13,400 bytes. A hybrid or pq-only
initiator MUST refuse a bundle without any ML-KEM prekey (SR-6, downgrade).

## 4. Handshake (Alice → Bob)

### 4.1 Alice

1. Verify the bundle for the chosen mode (§3): identity signatures, every prekey signature and
   expiry, presence of a PQ prekey. Hybrid requires **both** signatures everywhere.
2. Generate ephemeral `EK_A` (X25519), unless pq-only.
3. Compute, as the mode requires:
   `DH1 = DH(IKdh_A, SPK_B)`, `DH2 = DH(EK_A, IKdh_B)`, `DH3 = DH(EK_A, SPK_B)`,
   `DH4 = DH(EK_A, OPK_B)` (if an OPK was offered);
   `(CT, SS) = ML-KEM.Encaps(PQOPK_B if offered, else PQSPK_B)`.
4. Key schedule:
   ```
   SK          = HKDF-SHA256(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3 [|| DH4] || SS,
                             info = "PQChat-v1 X25519 MLKEM768 SHA256 AES256GCM")   (hybrid)
   k_msg || RK = HKDF-SHA256(salt = 0^32, ikm = SK, info = "PQChat-v1 handshake split", L = 64)
   ```
   Classical and pq-only use their own `info` labels, so keys of different modes never coincide.
   DH outputs, `SS`, `SK` and the HKDF input are wiped right after use (best effort, SR-15).
5. Associated data (SR-7, SR-37):
   ```
   PB = SHA-256("PQChat-v1 prekey binding" || flags u8 || key(X25519, SPK)
                [|| key(X25519, OPK)] [|| key(MLKEM768, PQ prekey used)])
   AD = IdentityPublic(A) || IdentityPublic(B) || PB
   ```
6. pq-only only: `transcript_sig = ML-DSA.Sign(IKsig_pq_A, ctx = label, header_unsigned || IdentityPublic(B))`.
7. Send `header || u16 len || AES-256-GCM(k_msg, nonce = 0^96, plaintext, AD || header)`.
   The zero nonce is safe because `k_msg` encrypts exactly one message.

### 4.2 Header

```
header = version u8 || mode u8 || kex u8 || sig u8 || aead u8 || IdentityPublic(A)
         || spk_id u32 || [key(X25519, EK_A)]                     (not in pq-only)
         || flags u8 (0x01 OPK used, 0x02 PQ prekey is one-time; other bits MUST be 0)
         || [opk_id u32] || [pq_id u32 || CT[1088]]                (KEM part not in classical)
         || [transcript_sig[3309]]                                 (pq-only only)
```

Measured sizes of the initial message with an empty plaintext:

| Mode | with one-time prekeys | last-resort only |
|---|---|---|
| classical | 5,457 B | 5,453 B |
| hybrid | 6,549 B | 6,545 B |
| pq-only | 9,821 B | 9,821 B |

Most of the size is Alice's `IdentityPublic` (5,392 B), dominated by her ML-DSA-65 key and the
ML-DSA signature over `IKdh`. The hybrid premium over classical is exactly `pq_id` + `CT` = 1,092 B.

### 4.3 Bob (order matters)

1. **Parse strictly** (max 32 KiB): version, mode, suite bytes, algorithm IDs, exact lengths, no
   unknown flags, no trailing bytes. Nothing cryptographic happens before this succeeds.
2. **Policy**: reject a mode the local policy does not allow (default: hybrid only).
3. Verify Alice's identity signatures for the mode.
4. **Replay check**: reject if `SHA-256(header)` is in the replay cache (SR-11).
5. pq-only: verify the transcript signature.
6. Look up the referenced prekeys (unknown IDs are rejected); reject an expired signed prekey.
7. Recompute the DH values, decapsulate `CT`, derive `k_msg`, `RK`, `AD` exactly as Alice.
8. Open the AEAD. Any failure is reported as a single `VerificationError`.
9. **Only after successful authentication**: delete the one-time prekeys used (SR-10) and add the
   header hash to the replay cache. Deleting earlier would let forged messages burn Bob's prekeys.

### 4.4 Safety numbers (SR-17)

For each user: `SHA-256("PQChat-v1 safety number" || key(ED25519) || key(MLDSA65) || key(X25519))`;
the first 30 bytes become six 5-digit groups (each 5-byte chunk mod 100000). The two 30-digit halves
are sorted and concatenated into 60 digits that are identical on both devices.

## 5. Ongoing messages

Specified in §6 of this document once Milestone 5 is complete; the design is in
`docs/notes/m5-pq-ratchet.md`. The handshake hands over `RK`, `AD`, Bob's signed prekey as the first
DH-ratchet public key, and Bob's signed ML-KEM prekey as the first PQ re-key target.

## 6. Double ratchet and post-quantum re-keying

See `docs/notes/m5-pq-ratchet.md` (normative for v1 until merged here).

## 7. Security properties and where they are checked

| Property | Mechanism | Evidence |
|---|---|---|
| Confidentiality if X25519 **or** ML-KEM holds | both in one HKDF | `tests/unit/test_handshake.py::test_sk_depends_on_every_input`; ProVerif (M4) |
| Authentication of prekeys against classical **and** quantum forgers | Ed25519 **and** ML-DSA-65 | `tests/negative/test_bundle.py` |
| Downgrade resistance | mode+suite in header, header in AEAD AD, policy | `tests/negative/test_downgrade.py` |
| Key binding | identities + PB in AD | `tests/negative/test_handshake_binding.py` |
| Replay resistance | one-time prekey deletion + replay cache | `tests/negative/test_opk_reuse.py`, `test_replay.py` |
| Strict parsing | encoding.py Reader | `tests/negative/test_parsing.py`, `tests/property/` |
| Any bit flip rejected | AEAD over header | `tests/property/test_bitflip.py` (300 Hypothesis cases) |
