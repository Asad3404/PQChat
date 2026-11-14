# ADR-002: Protocol v1 changes adopted from the threat model

* **Status:** accepted — student approved "adopt all 6" on 2026-11-06
* **Date:** 2026-11-09

## Context

The M1 threat model (§10) found six gaps in the version-1 design of PROJECT-BRIEF.md §5. PROJECT-BRIEF.md §2
rule 4 requires approval before changing §5. The student approved all six recommendations.

## Decision

| Req | Change | Protocol (§5) change? |
|---|---|---|
| SR-17 | Safety numbers; pin identity keys on first use; pause sending after a key change | No (client) |
| SR-18 | `created_at`/`expires_at` inside each signed prekey; clients reject expired prekeys | **Yes**, bundle format |
| SR-37 | `PB = SHA-256(label ‖ used prekey public keys)` appended to the AEAD AD | **Yes**, §5.2 step 5 |
| SR-21 | Relay authenticates clients with a signed challenge | No (relay API, M6) |
| SR-20 | Relay deletes on delivery, max retention 30 days | No (relay, M6) |
| SR-27 | Message history encrypted under a key-store-derived key | No (client, M6) |

PROJECT-BRIEF.md §5.1 and §5.2 were updated to match; `docs/protocol-spec.md` is normative.

## Consequences

* + Closes T-02, T-34, T-09, T-18, T-14, T-26 (see threat model).
* − Bundles grow by 16 bytes per prekey (two u64 times); the initial message is unchanged in size
  (PB is in the AD, not on the wire).
* − Clients need a roughly correct clock (assumption ASM-6).
