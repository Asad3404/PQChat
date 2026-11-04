# ADR-001: Build a pinned, minimal liboqs from source

* **Status:** proposed (Milestone 0)
* **Date:** 2026-11-04

## Context

ML-KEM-768 and ML-DSA-65 come from liboqs (C) through liboqs-python. CLAUDE.md §6 says to
build liboqs from source. Three risks have to be handled:

1. **Version drift.** Distro packages lag behind and might not implement the final FIPS
   203/204 versions of the algorithms.
2. **Silent auto-install.** If liboqs-python cannot find the C library at import time, it
   *downloads and compiles liboqs by itself* (into `~/_oqs`). That would bypass our pin and
   our review: an unexpected supply-chain path.
3. **Attack surface.** A default liboqs build contains dozens of algorithms we never use.

## Decision

* Build liboqs **0.16.0** with `scripts/install_liboqs.sh` everywhere (local, Docker, CI).
  The script checks that the tag resolves to commit
  `5a1a854b0dc9f2141bdc771c555ee60c37950183` and aborts if not.
* Use `-DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65"` and `-DOQS_BUILD_ONLY_LIB=ON`.
* Keep liboqs's default OpenSSL linkage (`libcrypto` for some symmetric primitives); it is the
  upstream default and the most widely tested configuration.
* Always set `OQS_INSTALL_PATH` in Docker and CI. The runtime Docker image contains no
  compiler or git, so the auto-install path cannot run there.
* Tests assert the exact liboqs version and the exact list of enabled algorithms. An
  auto-installed liboqs would be a full build with many algorithms, so the test would fail.

## Consequences

* + Reproducible builds; pin changes are a one-line, reviewable diff in one script.
* + Any accidental fallback to an unpinned liboqs is detected by the test suite.
* − Building takes about 1–2 minutes (cached in CI).
* − Adding another algorithm (e.g. ML-KEM-1024 for a benchmark) requires changing the
  minimal-build list and the test.
* Limitation to record in the thesis: liboqs is a research library; its own README says it
  is not recommended for production. That is acceptable for a capstone prototype.
