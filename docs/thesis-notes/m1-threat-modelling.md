# Thesis notes — threat modelling (Milestone 1)

> Draft notes to rewrite in your own words. Not final thesis text.

## Points for the methodology chapter

- **Why threat-model first?** Requirements derived from threats give every later design and test a
  reason to exist. Without it, controls are chosen by habit and gaps go unnoticed. M1 found six gaps
  in the initial protocol before any code was written (threat-model.md §10).
- **Why STRIDE-per-element?** It walks every element of the data-flow diagram through six fixed
  categories, which makes coverage checkable. Weakness: it finds threats by category, not by attack
  chain; attack trees or the M8 pentest complement it.
- **Why likelihood × impact (5 × 5)?** It is the most common qualitative scheme (NIST SP 800-30,
  ISO 31000), easy to explain, and shows each control's effect as inherent → residual risk.
  Weakness: the scores are subjective. Mitigation: each score has a short rationale, and the
  ranking matters more than the absolute numbers. DREAD was rejected because Microsoft itself
  dropped it for inconsistency.
- **Traceability as a test.** The chain threat → requirement → milestone → planned test is checked
  by `tests/unit/test_threat_model_traceability.py`, so the model cannot quietly drift out of sync
  as the project changes. This is a small but defensible methodological contribution.

## Points for the discussion chapter

- The highest accepted residual risk is **metadata visible to the relay** (T-15). PQ-Chat protects
  content, not the social graph; sealed sender or mixnets would be future work.
- **First-contact identity substitution** (T-02) cannot be solved by cryptography alone. It needs
  users to compare safety numbers, a known usability problem (cf. studies of Signal safety-number use).
- A4 has two forms: *passive* (harvest now, decrypt later) is countered by ML-KEM in key exchange;
  *active future* (forging signatures) is countered by ML-DSA. PQXDH only addresses the first; the
  dual signatures address the second.
