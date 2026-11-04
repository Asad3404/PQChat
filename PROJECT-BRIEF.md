# PROJECT-BRIEF.md — PQ-Chat: Post-Quantum Secure Messaging

> Project brief. Keep this file in the root of the repository.
> It is the single source of truth for this project.

---

## 1. The project in one paragraph

PQ-Chat is an end-to-end encrypted messenger that stays secure against a future quantum computer.
It combines **X25519** with **ML-KEM-768** (NIST FIPS 203) in a hybrid handshake modelled on Signal's **PQXDH**,
signs keys with **both Ed25519 and ML-DSA-65** (NIST FIPS 204), and protects ongoing chats with a
**double ratchet plus periodic ML-KEM re-keying**. The relay server is **untrusted** and only ever sees public keys
and ciphertext. The system must be designed, formally verified (ProVerif), attacked, forensically checked and
benchmarked. This is my **MS Cybersecurity capstone project**: I must understand and defend every design decision in a viva.

---

## 2. How we work together

**Implementation role:** design notes, code, tests, ProVerif models, attack scripts, benchmarks, figures, draft notes.
**My role (student):** approve designs, review and understand the code, run everything locally, write the thesis in my own words.

### Working rules
1. Work on **one milestone at a time, in order** (Section 9). Do not start the next milestone until I say "approved".
2. For every milestone follow this loop: **design note → tests → code → run tests → security scans → commit → report**.
3. **Never weaken, skip, or delete a test to make it pass.** If something fails, fix the code or tell me why.
4. **Ask me first** before: adding a dependency not listed in Section 6, changing the protocol in Section 5,
   or doing anything destructive (deleting files, rewriting git history, force-pushing).
5. Keep `docs/PROGRESS.md` updated: date, milestone, what was done, test results, open issues.
6. Make small commits with clear messages (Conventional Commits style, e.g. `feat(handshake): add ML-KEM encapsulation`).
7. **Explain as you go.** I am a master's student, so explain *why*, not just *what*. Use plain language first, then the technical term.
8. Anything written for the thesis goes in `docs/thesis-notes/` as **notes I will rewrite in my own words**. It is not final thesis text.
9. If you are unsure about a requirement, ask. Do not guess on security decisions.

### End-of-milestone report (always use this format)
- **What was built:** files and components
- **How to run it:** exact commands
- **Results:** tests passed/failed, coverage, Bandit/Semgrep/pip-audit output, ProVerif results if any
- **Concepts I must understand:** 3–6 bullets, each explained in plain language
- **Likely viva questions:** 5 questions with short model answers
- **Open issues / decisions needed from me**

---

## 3. Security rules (non-negotiable)

1. **Never implement cryptographic primitives yourself.** Use only:
   - `liboqs-python` → ML-KEM-768, ML-DSA-65
   - `cryptography` (pyca) → X25519, Ed25519, HKDF-SHA256, HMAC-SHA256, AES-256-GCM
   - `argon2-cffi` → Argon2id (passphrase → key-store key)
2. Randomness comes only from the crypto libraries or `secrets`/`os.urandom`. Never use `random`.
3. Compare MACs, tags and keys with `hmac.compare_digest` (constant time).
4. **Never log** private keys, shared secrets, plaintext or full ciphertexts. Add a test that checks log redaction.
5. The **server stores only public keys and ciphertext**: never plaintext, never private keys.
6. **Strict parsing:** check the version byte, algorithm IDs and exact/maximum length of every field.
   Reject unknown, oversized or truncated input **before** any cryptographic operation. No `pickle`, no `eval`.
7. **Domain separation:** every HKDF/HMAC use has its own unique `info`/label string.
8. AEAD **associated data** binds the full header and both parties' identity keys.
9. **Downgrade protection:** the mode and algorithm IDs are inside the authenticated transcript.
   A hybrid-capable client must refuse a classical-only session unless explicitly configured to allow it.
10. Private keys at rest are encrypted: Argon2id(passphrase) → AES-256-GCM.
11. Delete intermediate secrets (DH outputs, KEM shared secrets) right after deriving keys. Use `bytearray`
    for best-effort zeroization and document Python's limits.
12. Python itself is not constant-time. Keep all secret-dependent math inside the C libraries and record this as a limitation.

---

## 4. Threat model (summary — full version is produced in Milestone 1)

**Attackers**
- **A1 – Network attacker (Dolev-Yao):** reads, modifies, drops, replays and injects any message.
- **A2 – Malicious relay server:** controls the server and its database.
- **A3 – Device compromise:** steals a device or its key store at some point in time.
- **A4 – "Harvest now, decrypt later" quantum attacker:** records traffic today and can break X25519/Ed25519 in the future.

**Security goals:** confidentiality · mutual authentication · forward secrecy · post-compromise security ·
hybrid security (safe if *either* X25519 *or* ML-KEM holds) · replay resistance · downgrade resistance ·
minimal metadata · no plaintext or private keys at rest on the server.

**Out of scope:** malware with live memory access on the endpoint, anonymity against traffic analysis,
multi-device sync, group chats.

---

## 5. Protocol design — version 1

### 5.1 Keys per user
| Key | Algorithm | Lifetime | Notes |
|---|---|---|---|
| IKsig-ed | Ed25519 | long-term | identity signing key |
| IKsig-pq | ML-DSA-65 | long-term | identity signing key |
| IKdh | X25519 | long-term | identity DH key, signed by both IKsig keys |
| SPK | X25519 | rotated (e.g. weekly) | signed prekey |
| PQSPK | ML-KEM-768 | rotated | signed last-resort KEM prekey |
| OPK / PQOPK | X25519 / ML-KEM-768 | one-time | optional, deleted after use |

**Every prekey is signed with BOTH Ed25519 and ML-DSA-65. A bundle is valid only if both signatures verify.**
(PQXDH authenticates with elliptic curves only; dual signatures are this project's contribution towards quantum-resistant authentication.)

### 5.2 Hybrid handshake (Alice → Bob), PQXDH-style
1. Alice fetches Bob's prekey bundle from the relay and verifies both signatures on every prekey.
2. Alice generates an ephemeral X25519 key `EK_A`.
3. Compute:
   - `DH1 = DH(IKdh_A, SPK_B)`
   - `DH2 = DH(EK_A, IKdh_B)`
   - `DH3 = DH(EK_A, SPK_B)`
   - `DH4 = DH(EK_A, OPK_B)` (only if a one-time prekey was used)
   - `(CT, SS) = ML-KEM-768.Encaps(PQOPK_B or PQSPK_B)`
4. `SK = HKDF-SHA256(ikm = F || DH1 || DH2 || DH3 [|| DH4] || SS, salt = 32 zero bytes, info = "PQChat-v1 X25519 MLKEM768 SHA256 AES256GCM")`,
   where `F` = 32 bytes of `0xFF`.
5. `AD = Encode(identity public keys of A) || Encode(identity public keys of B)`.
6. Initial message = header (version, mode, algorithm IDs, Alice's identity public keys, `EK_A`, `CT`, prekey IDs)
   + AES-256-GCM(key from SK, plaintext, AD || header).
7. Bob verifies, decapsulates, derives the same `SK`, then deletes any one-time prekeys that were used.

### 5.3 Ongoing messages
- **Double ratchet** as in Signal's specification: X25519 DH ratchet, HMAC-SHA256 chain KDF, AES-256-GCM,
  header carries DH public key, PN and N. Maximum skipped message keys: 1000.
- **Post-quantum re-key (simplified SPQR):** each party advertises an ML-KEM-768 ratchet public key. Every K DH-ratchet steps
  (configurable, start with K = 4), the sender encapsulates to the peer's latest KEM key and mixes the secret into the root KDF:
  `(RK, CK) = HKDF(RK, DH_out || SS_kem)`.
  **Before coding Milestone 5, write the detailed design in `docs/notes/m5-pq-ratchet.md` and wait for my approval.**
  Document clearly that Signal's real SPQR uses the "ML-KEM Braid" with erasure coding, and that ours is a simplification.

### 5.4 Modes (for benchmarking and downgrade testing)
| Mode | Key establishment | Authentication |
|---|---|---|
| `classical` | X25519 only (X3DH-style) | Ed25519 |
| `hybrid` (default) | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 |
| `pq-only` | ML-KEM-768 only | ML-DSA-65, with Alice signing the transcript (benchmark-only variant; note that it loses deniability) |

### 5.5 Wire format
- Binary: version byte + mode byte + length-prefixed fields (big-endian u16/u32) with **fixed maximum sizes**.
- The server API uses JSON envelopes over WebSocket, with binary blobs in base64url. Every blob is strictly parsed.
- Plaintext is padded to size buckets (e.g. 256 / 1024 / 4096 bytes) before encryption (Milestone 7).

---

## 6. Tech stack (pin all versions in `pyproject.toml`)

| Area | Tools |
|---|---|
| Language | Python 3.12 |
| Post-quantum crypto | liboqs (build from source with CMake) + liboqs-python |
| Classical crypto | cryptography (pyca), argon2-cffi |
| Relay server | FastAPI, uvicorn, websockets, SQLite |
| Client UI | Local web UI: plain HTML + vanilla JavaScript + minimal CSS, served by the Python client on localhost. **Crypto never runs in the browser.** |
| Testing | pytest, hypothesis, pytest-benchmark, pytest-cov |
| Code quality and security | ruff, mypy (strict for `crypto/` and `protocol/`), bandit, semgrep, pip-audit, pre-commit |
| Formal verification | ProVerif (`opam install proverif`); Tamarin optional |
| Attack tooling | mitmproxy, OWASP ZAP (Docker image), Wireshark/tcpdump, a fuzzer (Atheris if it supports our Python version, otherwise Hypothesis) |
| Benchmarks and plots | pandas, matplotlib |
| Packaging and CI | Docker, Docker Compose, GitHub Actions |
| Compliance artefact | CBOM in CycloneDX JSON |

**Platform note:** if I am on Windows, set everything up inside **WSL2 (Ubuntu)** or Docker. liboqs builds most reliably on Linux.

---

## 7. Repository layout

```
pq-chat/
├── PROJECT-BRIEF.md
├── README.md
├── pyproject.toml
├── docker-compose.yml
├── docker/                    # Dockerfile.server, Dockerfile.client
├── .github/workflows/ci.yml   # tests, scans, ProVerif
├── src/pqchat/
│   ├── crypto/                # thin wrappers: kem.py, sig.py, dh.py, kdf.py, aead.py, keystore_crypto.py
│   ├── protocol/              # encoding.py, bundle.py, handshake.py, ratchet.py, pq_ratchet.py, session.py, modes.py
│   ├── client/                # keystore.py, relay_client.py, app.py (local UI server), static/
│   └── server/                # app.py (relay), storage.py, ratelimit.py
├── tests/                     # unit/, property/, vectors/, negative/, integration/
├── formal/                    # handshake.pv, ratchet_bounded.pv, RESULTS.md, run.sh
├── attacks/                   # mitm_prekey_swap.py, replay.py, downgrade.py, fuzz_parsers.py, key_compromise_demo.py
├── bench/                     # run_bench.py, results/ (CSV + PNG)
├── forensics/                 # image_and_search.py
├── evidence/                  # pcaps, scan reports, screenshots
└── docs/
    ├── PROGRESS.md
    ├── threat-model.md
    ├── protocol-spec.md
    ├── asvs-checklist.md
    ├── pentest-report.md
    ├── forensics.md
    ├── compliance.md
    ├── cbom.json
    ├── decisions/             # architecture decision records (ADR-001 …)
    ├── notes/                 # design note per milestone
    └── thesis-notes/          # drafts I will rewrite
```

---

## 8. Testing requirements

- **Test vectors:** X25519 (RFC 7748), HKDF (RFC 5869), AES-GCM, and ML-KEM-768 / ML-DSA-65 round-trips plus known-answer vectors where available.
- **Property tests (Hypothesis):** `decrypt(encrypt(m)) == m`; out-of-order delivery works; flipping any single bit in a header or ciphertext causes rejection.
- **Negative tests:** each of the two signatures invalid, wrong prekey ID, truncated or oversized fields, unknown version,
  replayed message, downgraded mode, reused one-time prekey.
- **Integration test:** two clients plus the relay in Docker Compose exchange 1,000 messages, including out-of-order and dropped messages.
- **Coverage:** at least 90% for `crypto/` and `protocol/`.
- **CI fails on:** any failing test, a Bandit high-severity finding, a Semgrep error, a pip-audit vulnerability, or any ProVerif query that should hold returning false.

---

## 9. Milestones (do them in order)

Each milestone maps to a phase of my methodology and to a course in my MS program.

| # | Milestone | Phase / course | Done when |
|---|---|---|---|
| M0 | **Setup:** repo, `pyproject.toml` with pinned deps, liboqs build, Dockerfiles, CI skeleton, pre-commit, `PROGRESS.md` | — | CI is green; `docker compose up` starts a relay stub; an ML-KEM-768 round-trip test passes |
| M1 | **Threat model:** `docs/threat-model.md` with a data-flow diagram (Mermaid), STRIDE table, attackers A1–A4, risk register (likelihood × impact), security requirements SR-1 … SR-n | Phase 2 · Security Risk Management | Every security requirement has an ID and a planned test |
| M2 | **Crypto wrappers** in `crypto/` + vector tests | Phase 3 · Applied Cryptography | All vector tests pass; 100% coverage of `crypto/` |
| M3 | **Hybrid handshake** + `docs/protocol-spec.md` (message formats, key schedule, reasons for each primitive) | Phase 3 · Applied Cryptography | Alice and Bob derive the same SK; all negative tests pass |
| M4 | **ProVerif handshake model** `formal/handshake.pv`: secrecy, mutual authentication (injective correspondence), forward secrecy, hybrid property (one run with X25519 broken, one with ML-KEM broken). Also show that `classical` mode **fails** against the harvest-now-decrypt-later attacker | Phase 4 · Security Protocols & Formal Methods | Intended queries proved; results table in `formal/RESULTS.md`; CI runs ProVerif |
| M5 | **Double ratchet + PQ re-key** (design note approved first) + bounded ProVerif model | Phases 3–4 | Out-of-order, forward-secrecy and post-compromise-security tests pass |
| M6 | **Relay server + client key store + local web UI** | Phase 5 · Secure Software Development | Two users chat in the browser via Docker Compose; `docs/asvs-checklist.md` (OWASP ASVS 5.0 Level 2) filled in |
| M7 | **Network hardening:** TLS 1.3, padding, rate limiting, prekey-exhaustion protection; Wireshark captures | Phase 6 · Network Security | Captures in `evidence/` show no plaintext; metadata-leakage analysis written |
| M8 | **Attack suite** in `attacks/`: MITM prekey swap (mitmproxy addon), replay, downgrade, fuzzing every parser, ZAP scan, key-compromise demo → `docs/pentest-report.md` with CVSS v4.0 scores | Phase 7 · Ethical Hacking & Penetration Testing | Every finding fixed and retested, with evidence |
| M9 | **Forensics:** scripts that image the relay DB and client data directory and search for plaintext/keys; incident-response playbook for a compromised relay | Phase 8 · Digital Forensics & IR | `docs/forensics.md` complete |
| M10 | **Governance:** mapping to NIST IR 8547 (deprecated after 2030, disallowed after 2035), NIST CSF 2.0, data-minimisation principles; CBOM | Phase 9 · Security Governance, Risk & Compliance | `docs/compliance.md` + `docs/cbom.json` |
| M11 | **Benchmarks:** 3 modes × metrics (handshake time, bundle size, first-message size, per-message overhead, re-key cost, CPU, memory); 1,000 runs; median + p95; hardware recorded | Phase 10 · Capstone | One command reproduces all CSVs and plots in `bench/results/` |
| M12 | **Thesis support:** figures (architecture, sequence diagram, results), demo script, polished README, viva-prep Q&A in `docs/thesis-notes/` | Phase 10 · Capstone | A fresh clone runs end-to-end by following only the README |

---

## 10. Ethics

- Attack only this system, inside an isolated Docker network.
- Use synthetic test accounts and messages only. No real personal data.
- AI-assisted development will be disclosed in the thesis as my university requires.

---

## 11. Key references

- NIST FIPS 203 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf
- NIST FIPS 204 (ML-DSA): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- NIST IR 8547, Transition to Post-Quantum Cryptography Standards (final, 27 Oct 2026)
- Signal PQXDH specification: https://signal.org/docs/specifications/pqxdh/
- Signal Double Ratchet specification: https://signal.org/docs/
- Signal SPQR / Triple Ratchet (Oct 2025): https://signal.org/blog/spqr/
- Bhargavan et al., Formal verification of PQXDH (USENIX Security 2024): https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan
- ProVerif: https://ocaml.org/p/proverif
- liboqs: https://github.com/open-quantum-safe/liboqs
- OWASP ASVS 5.0: https://owasp.org/projects/asvs
