# Digital forensics and incident response (Milestone 9)

**Question answered:** if an attacker (or an investigator) obtains the relay's database or a user's
data directory, what can they recover? **Tool:** `forensics/image_and_search.py`. **Evidence:**
`evidence/m9/case/report.json`. **Tests:** `tests/integration/test_forensics.py`.

## 1. Method

| Step | What | Why |
|---|---|---|
| 1. Acquisition | Copy every artefact — relay `relay.db` plus SQLite side files (`-wal`, `-shm`, `-journal`), each client's data directory — into a case folder | Recent SQLite changes live in the WAL; missing it misses data |
| 2. Integrity | SHA-256 of the source before copying and of the image after; analysis only if they match; UTC acquisition time recorded | Chain of custody: shows the evidence was not altered |
| 3. Ground truth | In the synthetic demo scenario every secret is known: passphrase, all message texts, identity private keys, prekey secrets, session root keys, and the ciphertexts of already-delivered messages | Searching for *known* secrets turns "we found nothing" into a measurable claim |
| 4. Byte search | Each secret in four encodings (raw, hex, base64, base64url), as aligned 33-byte fragments, over every imaged byte (including free pages) | Catches values stored in any common text form and values split by the storage engine |
| 5. Positive controls | Two items that **must** be found: the ciphertext still queued for an offline user, and a public identity key | Proves the search works; without controls "0 hits" proves nothing |
| 6. Structured analysis | Read-only SQLite inspection of the image: tables, columns, row counts, usernames, queued message metadata, free-page count | Describes the metadata an attacker gets |

### Scenario (`--demo`)

In-process relay with an on-disk database, two clients (alice, bob). Alice sends a message, Bob
replies (both delivered and acknowledged, so deleted on the relay), Bob goes offline, Alice sends a
third message (stays queued). Then the relay database and both client directories are imaged.

## 2. Results

| Item | Result |
|---|---|
| Images (relay.db, alice/keystore.pqks, bob/keystore.pqks) | 3 files, all hashes verified |
| Secrets searched | 20 (passphrase; 3 message texts; per user: Ed25519 and X25519 identity private keys, ML-DSA-65 `K` and `s1‖s2‖t0`, ML-KEM-768 `dk_PKE` and `z`, session root key; ciphertexts of 2 delivered messages) × 4 encodings |
| **Hits** | **0** |
| Positive controls | 2 / 2 found (queued ciphertext, public ML-DSA key) |
| What the relay database **does** reveal | usernames `alice`, `bob`; their public identity keys; 4 signed and 198 one-time public prekeys; one queued message: recipient `bob`, sender `alice`, kind `msg`, 323 bytes (padded) |

**Conclusion.** SR-19 (relay holds no plaintext or private keys), SR-20 (delivered messages are gone,
including from the file's free pages, thanks to `PRAGMA secure_delete=ON`), SR-26 and SR-27 (client
keys and history only encrypted) are confirmed forensically. What remains on the relay is the
metadata already accepted in the threat model (T-15).

## 3. Two methodology lessons (useful for the thesis)

1. **Long values are not contiguous in SQLite.** A row bigger than one page continues in overflow
   pages, each starting with a 4-byte page pointer. A naive search for a 1,952-byte public key found
   nothing although the key *is* stored — the positive control exposed this. Fix: search aligned
   33-byte fragments (33 is a multiple of 3, so base64 fragments align too).
2. **Post-quantum secret keys contain public material.** An ML-KEM-768 decapsulation key is
   `dk_PKE ‖ ek ‖ H(ek) ‖ z` (FIPS 203), so 35 of its 72 fragments are the public key. The first run
   therefore reported "ML-KEM secret key fragments on the relay" — a false positive, because the relay
   stores the public key. Similarly the ML-DSA secret key starts with the public seed ρ and contains
   tr = H(pk) (FIPS 204). Fix: search only the truly secret components.

## 4. Limits

* The scenario is synthetic and small; a long-running relay would also need its filesystem's
  unallocated space and backups examined (`secure_delete` only covers SQLite's own pages).
* Memory forensics of a running client is out of scope (PROJECT-BRIEF.md §4); best-effort zeroisation in
  Python cannot guarantee secrets are gone from RAM (T-27).
* Real deployments may log IP addresses at the reverse proxy; PQ-Chat's relay logs neither IPs nor
  usernames.

## 5. Incident-response playbook: compromised relay

Structured along the NIST SP 800-61 incident-handling life cycle. Key fact for every decision: a
compromised relay **cannot read messages or impersonate users who have verified safety numbers**;
it can see metadata, withhold messages and attempt first-contact impersonation (pentest F-01).

| Phase | Actions |
|---|---|
| **Preparation** | Keep relay host and container images reproducible (pinned digests, CI build); keep the relay's TLS key and the deployment config in a separate secret store; enable host audit logging; document this playbook; make sure clients pin identities (SR-17). |
| **Detection and analysis** | Triggers: unexpected container image digest; unknown processes or outbound connections; users reporting *safety number changed* for contacts who did not reinstall; sudden prekey exhaustion; spike in `bad_prekey`/`auth_failed`. Image the host and `relay.db` (+WAL) with `forensics/image_and_search.py` before changing anything; hash and timestamp. Check the `accounts` table for identity keys that changed or names registered unexpectedly. |
| **Containment** | Take the relay offline or behind maintenance mode; revoke and rotate the relay TLS certificate and key; block administrative access paths; preserve the database image. Clients keep their keys: nothing secret was on the relay. |
| **Eradication** | Rebuild the relay from a clean, pinned image (`docker compose build` from a verified commit); restore **no** data from the compromised database except, optionally, the `accounts` table after checking each identity key against users' own pinned keys. |
| **Recovery** | Start the clean relay with a new TLS key. Clients re-register or log in and **upload fresh signed and one-time prekeys** (stale prekeys may have been tampered with or harvested). Ask users to re-verify safety numbers for sensitive contacts; any *key changed* warning during the incident window is treated as suspicious. Queued messages lost in the rebuild must be re-sent (they were only ciphertext). |
| **Post-incident** | Write a timeline and root cause; update the threat model's likelihood for T-02/T-13/T-18; consider key transparency to detect identity substitution automatically; check whether metadata exposure (who talked to whom) requires notification under the applicable data-protection law (see `docs/compliance.md`). |

### Specific questions an investigator must answer

1. Was any identity key in `accounts` replaced? (Compare with the users' pinned keys.)
2. Were bundles served with substituted prekeys? (Clients' TOFU warnings; relay access logs if any.)
3. Which metadata was exposed, for which period? (Queue table, logs, network captures.)
4. Was the relay used to exhaust one-time prekeys? (Prekey counts over time, rate-limit logs.)
