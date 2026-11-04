# Design note — Milestone 0: project setup

**Status:** implemented, awaiting student approval
**Date:** 2026-11-04

## Goal

Create a reproducible, secure-by-default foundation, so every later milestone builds on
the same pinned tools. "Done when" (PROJECT-BRIEF.md §9): CI is green; `docker compose up`
starts a relay stub; an ML-KEM-768 round-trip test passes.

## Decisions

| # | Decision | Why |
|---|---|---|
| D1 | liboqs **0.16.0** built from source by `scripts/install_liboqs.sh`, tag checked against its commit hash | One script is the single source of truth for local, Docker and CI. Checking the commit detects a moved/re-tagged release (supply-chain defence). See ADR-001. |
| D2 | **Minimal liboqs build**: only ML-KEM-768 and ML-DSA-65 | Smaller attack surface, faster build, and a test can prove no other algorithm is present. See ADR-001. |
| D3 | liboqs-python **0.16.0.2** (matches the C library's minor version) | A mismatch makes liboqs-python warn, and our pytest config turns warnings into errors. |
| D4 | Direct dependencies pinned exactly in `pyproject.toml`; **all** transitive dependencies pinned in `requirements/constraints.txt` | Benchmarks (M11) and Docker images must be reproducible. pip-audit scans the full constraints file, not just the direct dependencies. |
| D5 | Semgrep installed in its own virtualenv | It pins many of its own dependencies and would conflict with the runtime set. |
| D6 | Project-specific Semgrep rules (`.semgrep/pqchat-rules.yml`) with rule self-tests | Turns PROJECT-BRIEF.md §3 rules (no `random`, no pickle/eval, constant-time comparison, no raw hazmat ciphers) into checks that run on every commit. |
| D7 | mypy **strict for the whole package**, not just `crypto/` and `protocol/` | Stricter than required, at almost no cost. |
| D8 | ruff `T20` rule bans `print()` in library code | Stray `print()` debugging is a common way secrets end up in logs (PROJECT-BRIEF.md §3.4). |
| D9 | Docker: two-stage build, base image pinned **by digest**, non-root user (uid 10001), read-only root FS, `cap_drop: ALL`, `no-new-privileges`, port published on 127.0.0.1 only | Defence in depth for the relay container; the runtime image has no compiler or git, so liboqs-python cannot silently fetch and build another liboqs. |
| D10 | Relay stub disables `/docs`, `/redoc`, `/openapi.json` and the `Server` header | An untrusted, internet-facing relay should not advertise its API or software version. |
| D11 | Self-test runs during `docker build` | A broken PQ library fails the build instead of failing at runtime. |
| D12 | No HTTP-client test dependency (`httpx`) added | The brief requires approval for unlisted dependencies; tests use `urllib` from the standard library against a real uvicorn server instead. |

## What the M0 tests prove

* liboqs is exactly version 0.16.0 and contains exactly ML-KEM-768 and ML-DSA-65.
* ML-KEM-768 round-trip: encapsulator and decapsulator get the same 32-byte secret; key and
  ciphertext sizes match FIPS 203 (ek 1184, dk 2400, ct 1088).
* Encapsulation is randomised (two encapsulations differ).
* **Implicit rejection:** a tampered ciphertext does *not* raise an error; it yields a
  different, pseudo-random secret. Consequence for M3: the KEM ciphertext must be
  authenticated by the AEAD/transcript, because decapsulation alone never "fails".
* A wrong-length public key is rejected.
* ML-DSA-65 sign/verify with FIPS 204 sizes (pk 1952, sk 4032, sig 3309); modified message
  or signature is rejected.
* The self-test prints one short status line and no key material.
* The relay stub answers `/healthz`, hides API docs, and sends no `Server` header.

## Not in scope for M0

Crypto wrappers (M2), protocol (M3), ProVerif CI job (M4), real relay (M6), TLS (M7).
