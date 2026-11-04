# Design note — Milestone 1: threat model

**Status:** implemented, awaiting student approval
**Date:** 2026-11-04
**Deliverable:** [`docs/threat-model.md`](../threat-model.md)

## Goal

Before any protocol code exists, write down what we protect, from whom, how it could be
attacked and what the system must do about it. "Done when" (PROJECT-BRIEF.md §9): **every
security requirement has an ID and a planned test.**

## Method

| Step | Method | Why this one |
|---|---|---|
| 1. Scope | Assets (AS-n), assumptions (ASM-n), out-of-scope list | A threat model is only meaningful relative to what is protected and what is assumed. |
| 2. Model the system | Data-flow diagram (Mermaid) with elements E1–E7 and trust boundaries TB-1–TB-6 | Attacks happen where data crosses a trust boundary; the diagram makes those crossings visible. |
| 3. Attackers | A1–A4 from PROJECT-BRIEF.md §4, each with "can / cannot / how modelled in ProVerif" | Fixing capabilities now means M4 (ProVerif) and M8 (pentest) test against the *same* attackers. |
| 4. Find threats | **STRIDE-per-element** (Microsoft SDL; Shostack, *Threat Modeling*, 2014) | Systematic: every element is checked against all six categories, so whole classes of threat are not forgotten. |
| 5. Prioritise | **Risk register**, likelihood × impact on a 1–5 scale (5 × 5 matrix, ISO 31000 / NIST SP 800-30 style), scored before and after mitigation | Simple, explainable in a viva, and shows the *effect* of each control (inherent → residual risk). DREAD was not used: it is deprecated by Microsoft for being too subjective. |
| 6. Requirements | **SR-n**: one testable statement each, with threats, milestone, planned verification and status | Gives the traceability chain threat → requirement → code → test/proof → evidence. |
| 7. Check | `tests/unit/test_threat_model_traceability.py` parses the tables | The "done when" criterion is machine-checked in CI, and stays true as the document is edited. |

## What the traceability test enforces

* IDs are unique and numbered without gaps (threats `T-nn`, requirements `SR-n`).
* Every threat appears exactly once in the risk register; scores equal L × I; residual risk
  is never higher than inherent risk.
* A threat treated as *Mitigate* names at least one SR; one treated as *Accept* has a written rationale.
* Every SR names ≥ 1 existing threat, a milestone (M0–M12), a planned verification and a status.
* Threat → SR links in the register and SR → threat links in the requirements table agree in
  both directions.
* All six STRIDE categories and all four attackers A1–A4 occur; every security goal G-n is
  covered by at least one SR.

## Findings that need a decision (summary — details in threat-model.md §9)

The analysis found gaps in the version-1 protocol of PROJECT-BRIEF.md §5. Requirements that close
them are marked **Proposed** and are *not* adopted until the student approves:

* **SR-17** safety numbers + key-change warnings (the relay can otherwise swap a user's *identity* keys on first contact).
* **SR-18** expiry time inside the signed prekey data (stops replay of old, validly signed prekeys).
* **SR-37** hash of the used prekey public keys in the AEAD associated data (key binding, cf. Bhargavan et al. 2024).
* **SR-20** relay message-retention limit; **SR-21** relay authentication; **SR-27** message history at rest.
