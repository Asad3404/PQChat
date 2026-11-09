# Design note — Milestone 3: hybrid handshake

**Status:** implemented (review after M12, as agreed on 2026-11-06)
**Spec:** the normative description is [`docs/protocol-spec.md`](../protocol-spec.md); this note records
the design choices and their reasons.

## Approved changes to CLAUDE.md §5 (2026-11-06, "adopt all 6")

| Req | Change | Where |
|---|---|---|
| SR-18 | Every prekey carries `created_at` / `expires_at` inside the signed data; expired or over-long-lived prekeys are rejected. | bundle format |
| SR-37 | The AEAD associated data ends with `PB = SHA-256(label ‖ encoded prekey public keys used)`. | §5.2 step 5 |
| SR-17 | Safety numbers over both users' identity keys (`protocol/safety.py`); UI in M6. | new |
| SR-21 / SR-20 / SR-27 | Relay auth, retention, encrypted history | M6 |

Recorded in [ADR-002](../decisions/ADR-002-protocol-v1-changes.md); CLAUDE.md §5 updated to match.

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | All users always hold all identity keys (Ed25519, ML-DSA-65, X25519). The *mode* decides which are used and verified. | One identity format; modes stay comparable for benchmarks. |
| D2 | `IKdh` is signed by both signing keys, over the encoding of all three identity public keys. | Binds the three keys into one identity, so a relay cannot mix keys from two users. |
| D3 | Every field is type-tagged (algorithm ID byte) and has a fixed or bounded length; parsers reject trailing bytes. | SR-8/SR-9: unambiguous, canonical encoding; one byte string has exactly one meaning. |
| D4 | The *mode* fixes the algorithm suite exactly. A message whose suite bytes don't match its mode is rejected, and both are in the AEAD AD. | SR-6: downgrade needs to change authenticated bytes. |
| D5 | Default policy accepts **hybrid only**. `classical` needs `allow_classical=True`; `pq-only` needs `allow_pq_only=True` (benchmarks). | SR-6, SR-34. |
| D6 | SK is split with HKDF into a one-time first-message key and the initial ratchet root key. The first-message AEAD nonce is all zeros, which is safe because that key is used exactly once. | Clean hand-over to the M5 ratchet; never reuse SK directly. |
| D7 | Replay cache keyed on SHA-256 of the initial-message *header*, kept until the newest signed-prekey lifetime has passed. | SR-11. With a one-time prekey, deletion already stops replays (SR-10); the cache covers last-resort prekeys. |
| D8 | Time is passed in as an argument (`now`), never read inside protocol code. | Deterministic tests for expiry; no hidden clock. |
| D9 | `pq-only`: no DH. Alice signs the transcript (header + Bob's identity) with ML-DSA-65. | Matches CLAUDE.md §5.4; loss of deniability documented. |

## Tests planned → files

| Requirement | Test |
|---|---|
| SK equal on both sides, all modes | `tests/unit/test_handshake.py` |
| SR-4: SK depends on every DH and on SS | `test_handshake.py::test_sk_depends_on_every_input` |
| SR-5: each signature invalid separately | `tests/negative/test_bundle.py` |
| SR-18: expired / future / over-long prekey | `tests/negative/test_bundle.py` |
| SR-6: stripped PQ prekey, mode byte changed, suite mismatch, policy | `tests/negative/test_downgrade.py` |
| SR-7: any single bit flip in header or ciphertext rejected | `tests/property/test_bitflip.py` (Hypothesis) |
| SR-8: encode/decode round trip, canonical | `tests/property/test_encoding.py` (Hypothesis) |
| SR-9: truncated, oversized, unknown version/alg, trailing bytes | `tests/negative/test_parsing.py` |
| SR-10: reused one-time prekey | `tests/negative/test_opk_reuse.py` |
| SR-11: replayed initial message | `tests/negative/test_replay.py` |
| SR-37: wrong prekey binding | `tests/negative/test_handshake_binding.py` |
| SR-17: safety numbers equal on both sides, change when a key changes | `tests/unit/test_safety_number.py` |
| SR-34: pq-only refused by default | `tests/unit/test_modes.py` |
