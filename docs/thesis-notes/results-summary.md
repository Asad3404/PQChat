# Results summary for the thesis (notes to rewrite in your own words)

One page per methodology phase: the claim, the number, where the evidence is.

| Phase / chapter | Key result | Number | Evidence |
|---|---|---|---|
| 2 Risk management | Threat model drives everything | 36 threats, 37 requirements, all Done with cited evidence, machine-checked | `docs/threat-model.md`, `tests/unit/test_threat_model_traceability.py` |
| 3 Applied crypto | Wrappers are correct | RFC vectors + 85 NIST ACVP vectors; 100 % coverage of `crypto/` | `tests/vectors/` |
| 3 Applied crypto | Handshake agrees in every mode, rejects tampering | 300 random bit flips rejected; SK depends on every input | `tests/property/test_bitflip.py`, `tests/unit/test_handshake.py` |
| 4 Formal methods | Hybrid secrecy holds if either primitive is broken; classical falls to HNDL | 14 / 14 ProVerif results as predicted | `formal/RESULTS.md` |
| 4 Formal methods | Limitation: initiator authentication is classical | attack found with X25519/Ed25519 broken | same, pentest F-02 |
| 3–4 Ratchet | Only ML-KEM re-keying heals against a quantum thief | quantum attacker reads K/2 rounds, classical 2 | `tests/unit/test_ratchet_pcs.py`, `formal/ratchet_bounded.pv` |
| 5 Secure SDLC | Working system, two users in the browser | Compose + browser E2E; ASVS 5.0 L2 checklist | `evidence/m6/`, `docs/asvs-checklist.md` |
| 6 Network security | No plaintext on the wire; transport is hybrid PQ | TLS 1.3, X25519MLKEM768, 0 plaintext hits | `evidence/m7/`, `docs/notes/m7-network.md` |
| 6 Network security | What metadata remains | sender/recipient/timing at the relay | same, §3 |
| 7 Pentest | Attacks resisted and findings fixed | 10 findings, 7 fixed + retested, 2 design limits; 200,000 fuzz inputs, 0 crashes; ZAP 0 FAIL | `docs/pentest-report.md` |
| 8 Forensics | Seized relay/client data reveal no secrets | 20 secrets × 4 encodings, 0 hits, 2/2 positive controls | `docs/forensics.md` |
| 9 GRC | Transition plan to 2035; CBOM | 27 CBOM components; 4 quantum-vulnerable components, none used alone | `docs/compliance.md`, `docs/cbom.json` |
| 10 Capstone | PQ costs bandwidth, not CPU | +0.3 ms per handshake; 67× bundle payload; 4.5× mean message at K = 4 | `docs/notes/m11-benchmarks.md` |

## Bugs and lessons worth a discussion section

Each was found by a test, a tool or a review, then fixed with a regression test. Discussing them
shows the method worked:

1. A wrong post-compromise expectation in my own test (the stolen state already contains the next
   sending key) — corrected, made stricter.
2. The quantum healing test first could not distinguish DH healing from ML-KEM healing (K = 4 makes
   them coincide) — fixed by testing K = 8 and 12; became the K trade-off result.
3. Rate limiting disconnected normal users; per-target limit not wired in — found by integration tests.
4. Bob's first reply silently started a second handshake — found by *looking at a screenshot*
   (49 instead of 50 prekeys) → ADR-003.
5. ZAP found a method-less form and a re-unlock problem.
6. Forensics: a "0 hits" result was partly a false negative (SQLite overflow pages) and a later
   "hit" was a false positive (ML-KEM secret keys embed their public key) — both caught by positive
   controls and by reading FIPS 203.
7. ProVerif: the first model did not terminate; restructuring (fixed peers) and a lighter agreement
   query made it terminate; injectivity is argued from tests instead.
