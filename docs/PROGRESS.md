# Progress log

## 2026-11-04 — M0 Setup

**Status:** complete, awaiting approval.

**Done**
- Repository layout from CLAUDE.md §7; `CLAUDE.md`, `README.md`.
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
- The sandbox used for development blocks `deb.debian.org` and `semgrep.dev`, so the Docker
  *build* stage (apt + liboqs compile) and Semgrep *registry* rulesets were not run locally.
  The first GitHub Actions run is their real test.
- GitHub Actions are pinned by major tag, not commit SHA (hardening item for M8).
