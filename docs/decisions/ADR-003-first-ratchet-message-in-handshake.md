# ADR-003: Alice's first double-ratchet message travels inside the handshake

* **Status:** accepted by the implementer during M6 (2026-11-09); **needs the student's review**,
  because it refines CLAUDE.md §5.2 step 6.
* **Date:** 2026-11-09

## Context

In the first implementation the initial message encrypted the user's first plaintext directly
under `k_msg` (CLAUDE.md §5.2 step 6). The ratchet started only afterwards, so Bob's ratchet had no
sending chain until he received a ratchet message from Alice. When Bob wanted to reply first, the
client silently ran a second handshake in the opposite direction. Visible symptom in the M6
screenshot: Alice's one-time prekey count dropped to 49 although only she had started a chat.
Consequences: one wasted one-time prekey per conversation (helps prekey exhaustion, T-16), Alice's
session silently replaced, extra 8 KB per conversation start (pentest F-05, CVSS 6.3).

## Decision

The plaintext encrypted under `k_msg` is now **Alice's first double-ratchet message** (header with her
first ratchet public key and ML-KEM announcement, body = the padded user text). Bob runs a normal
ratchet receive step on it after the handshake, which gives him a sending chain immediately. This is
how Signal combines X3DH/PQXDH with the double ratchet.

Implementation: `handshake.initiate(..., payload_builder=…)` calls back after the key schedule;
`Session.initiate` builds the ratchet message there; `Session.accept` decrypts it.
Limits raised accordingly: first payload ≤ 24 KiB, initial message ≤ 40 KiB.

## Consequences

* + Bob can answer at once (`test_bob_can_reply_right_after_the_handshake`); no hidden second
  handshake; one-time prekeys used only once per conversation.
* + The first message is protected twice: AES-GCM under `k_msg` (handshake AD) and the ratchet's own
  AES-GCM under the first message key (ratchet AD).
* − The initial message grows by the ratchet header (47 B + 1,189 B KEM announcement) and padding:
  hybrid ≈ 8.1 KB instead of ≈ 6.5 KB.
* No change to the key schedule, the AD, or any ProVerif query (the model abstracts the payload).
