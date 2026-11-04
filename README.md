# PQ-Chat

An end-to-end encrypted messenger designed to stay secure against a future quantum computer.
It combines X25519 with ML-KEM-768 (FIPS 203) in a PQXDH-style hybrid handshake, signs keys with
both Ed25519 and ML-DSA-65 (FIPS 204), and uses a double ratchet with periodic ML-KEM re-keying.
The relay server is untrusted: it only ever sees public keys and ciphertext.

MS Cybersecurity capstone project. The full project brief is in [`CLAUDE.md`](CLAUDE.md);
progress is tracked in [`docs/PROGRESS.md`](docs/PROGRESS.md).

> **Status: Milestone 0 (setup).** There is no messaging yet: only the toolchain, a relay
> health-check stub and an ML-KEM-768 / ML-DSA-65 self-test.

## Requirements

- Linux (on Windows, use WSL2 with Ubuntu 24.04)
- Python 3.12
- CMake ≥ 3.18, Ninja, a C compiler, OpenSSL headers, git
- Docker with the Compose plugin (optional for local development, used by CI)

On Ubuntu 24.04:

```bash
sudo apt-get install -y python3.12 python3.12-venv build-essential cmake ninja-build libssl-dev git
```

## Setup

1. Build liboqs 0.16.0 from source (installs to `/usr/local`):

```bash
sudo scripts/install_liboqs.sh
```

   Or install without root to a folder inside the repo, and tell liboqs-python where it is:

```bash
scripts/install_liboqs.sh "$PWD/.liboqs"
```

```bash
export OQS_INSTALL_PATH="$PWD/.liboqs"
```

2. Create the virtualenv and install pinned dependencies:

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -c requirements/constraints.txt -e '.[dev]'
```

3. Install the git hooks:

```bash
.venv/bin/pre-commit install
```

4. Check that the post-quantum library works:

```bash
.venv/bin/python -m pqchat.selftest
```

Expected output: `liboqs 0.16.0: ML-KEM-768 OK, ML-DSA-65 OK`

## Running the checks

```bash
.venv/bin/pytest --cov=pqchat
```

```bash
.venv/bin/pre-commit run --all-files
```

```bash
.venv/bin/pip-audit --strict -r requirements/constraints.txt
```

Semgrep is kept in its own virtualenv because it pins many of its own dependencies:

```bash
python3.12 -m venv .semgrep-venv && .semgrep-venv/bin/pip install semgrep==1.183.0
```

```bash
.semgrep-venv/bin/semgrep --test --metrics=off --config .semgrep/pqchat-rules.yml .semgrep/pqchat-rules.py
```

```bash
.semgrep-venv/bin/semgrep scan --error --metrics=off --config .semgrep/pqchat-rules.yml --config p/python --config p/security-audit src tests
```

## Docker

```bash
docker compose up --build
```

In another terminal:

```bash
curl http://127.0.0.1:8000/healthz
```

```bash
docker compose run --rm client
```

## Repository layout

See [`CLAUDE.md` §7](CLAUDE.md#7-repository-layout). Directories for later milestones
(`formal/`, `attacks/`, `bench/`, `forensics/`, `evidence/`) exist but are empty for now.
