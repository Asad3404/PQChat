# Progress log

## 2026-11-04 — M1 Threat model

**Status:** complete, awaiting approval.

**Done**
- `docs/threat-model.md`: 9 assets, 7 assumptions, Mermaid data-flow diagram (7 elements, 7 flows,
  6 trust boundaries), attackers A1–A4 with ProVerif/pentest mapping, 9 security goals,
  36 STRIDE threats, 5 × 5 risk register (inherent and residual), 37 security requirements.
- `tests/unit/test_threat_model_traceability.py`: 10 checks that make the "done when" criterion machine-checked.
- Design note `docs/notes/m1-threat-model.md`; thesis notes `docs/thesis-notes/m1-threat-modelling.md`.

**Results**
- pytest: 23 passed (13 from M0 + 10 traceability checks). Mutation check: 4 deliberately broken
  versions of the threat model (empty planned test, broken link, wrong score, unjustified acceptance) were each caught.
- ruff, mypy, Bandit, Semgrep project rules: clean.

**Open issues / decisions needed**
- 6 *Proposed* requirements need approval: SR-17 safety numbers, SR-18 prekey expiry (bundle format change),
  SR-37 prekey binding in AD (protocol change), SR-20 retention, SR-21 relay auth, SR-27 history at rest.
- The Mermaid diagram was syntax-checked by hand, not rendered locally (renderer download blocked in the sandbox).


## 2026-11-04 — M0 Setup

**Status:** approved 2026-11-04. GitHub Actions run #1: all jobs green.

**Done**
- Repository layout from PROJECT-BRIEF.md §7; `PROJECT-BRIEF.md`, `README.md`.
- `pyproject.toml` with exact pins; full transitive lock in `requirements/constraints.txt`.
- liboqs 0.16.0 built from source (minimal: ML-KEM-768 + ML-DSA-65) via `scripts/install_liboqs.sh`; liboqs-python 0.16.0.2.
- Relay stub (`pqchat.server`, `/healthz`), client self-test entry point (`pqchat.client`).
- Dockerfiles (two-stage, digest-pinned base, non-root, read-only), `docker-compose.yml`.
- GitHub Actions CI: lint/type/test, security scans, Docker build + compose smoke test.
- pre-commit (standard hooks, detect-private-key, ruff, mypy, bandit).
- Project-specific Semgrep rules with rule self-tests.
- Design note `docs/notes/m0-setup.md`, ADR-001.

**Results (local, Ubuntu 24.04, Python 3.12.3, Intel Xeon @ 2.10 GHz)**
- pytest: 13 passed, 0 failed.
- ruff, ruff format, mypy --strict: clean. Bandit: no findings. pip-audit: no known vulnerabilities.
- Semgrep project rules: 0 findings; rule self-test 5/5.
- Docker (runtime stage): relay healthy, `/healthz` 200, `/docs` 404, runs as uid 10001; client self-test OK.

**Open issues**
- ~~Docker build stage and Semgrep registry rulesets not run locally~~ — resolved: both passed in GitHub Actions run #1.
- GitHub Actions are pinned by major tag, not commit SHA (hardening item for M8).
