# Viva preparation: questions and model answers

> Notes for the student. Read each answer, check it against the evidence named, and say it in your
> own words. Examiners probe *why*; every answer below says why and where the evidence is.

## A. Motivation and design

**1. Why hybrid and not ML-KEM alone?**
ML-KEM is young; a classical attack on it (or an implementation bug) is possible. X25519 is well
studied but falls to a quantum computer. Feeding both secrets into one HKDF means an attacker must
break both. ProVerif proves secrecy with X25519 broken *and* with ML-KEM broken (`formal/RESULTS.md`).

**2. Why sign with both Ed25519 and ML-DSA-65?**
So that a *future active* quantum attacker cannot forge prekeys. PQXDH signs prekeys with
Ed25519 only, so it protects confidentiality against "harvest now, decrypt later" but not
authentication against an active quantum adversary. Requiring both signatures means forging needs
both schemes broken (SR-5, `tests/negative/test_bundle.py`).

**3. Why ML-KEM-768 / ML-DSA-65 and not 512/44 or 1024/87?**
Category 3 (≈ AES-192) is the level Signal's PQXDH and hybrid TLS deployments use; it balances
margin against size. The benchmarks show size, not CPU, is the cost, so going to 1024/87 would
mostly add bandwidth.

**4. What exactly does the relay learn?**
Usernames, public keys, and for each queued message: sender, recipient, time and padded size. No
content, no private keys (forensics: 0 hits for 20 secrets in 4 encodings, with positive controls).
That metadata leak is accepted risk T-15.

**5. Why is the relay "untrusted" and what does that change in the design?**
Everything the relay hands out is verified by the client (signatures, expiry, identity pinning);
everything it stores is public or ciphertext; it authenticates users by signatures, not passwords.
A relay compromise therefore exposes metadata, not messages (IR playbook, `docs/forensics.md`).

## B. Handshake

**6. Walk me through the key schedule.**
Four X25519 DH values and the ML-KEM shared secret, prefixed by 32 × 0xFF, go into HKDF-SHA256 with a
mode-specific label → SK. SK is split with HKDF into a one-time first-message key and the initial root
key. Figure: `docs/figures/key-schedule.png`.

**7. Why the 0xFF prefix F?**
Copied from X3DH/PQXDH: it gives domain separation from other uses of the curve and keeps the
construction aligned with the analysed Signal design.

**8. What is the prekey binding (PB) and why did you add it?**
A SHA-256 hash of the exact prekey public keys used, placed in the AEAD associated data (SR-37). It
binds the session to those keys, following the key-binding concerns raised in the PQXDH analysis by
Bhargavan et al. Test: redirecting the KEM prekey id to another valid key of Bob fails.

**9. ML-KEM decapsulation never fails. Is that a problem?**
No, it is a feature (implicit rejection, FIPS 203): a tampered ciphertext gives a random secret,
and the AEAD then fails. It means the KEM ciphertext must be authenticated, which it is (header in
AD). Test: `test_mlkem768_implicit_rejection_on_tampered_ciphertext`; NIST vectors include invalid
ciphertexts.

**10. How do you stop downgrade attacks?**
Mode and algorithm suite are in the header, the header is in the AEAD AD, the suite must match the
mode, and the default policy accepts hybrid only. A relay that strips ML-KEM prekeys makes the client
refuse (`attacks/downgrade.py`: 5/5 blocked; ProVerif: classical falls to HNDL).

**11. Replays?**
One-time prekeys are deleted after successful authentication (not before, or forged messages could
burn them); a replay cache covers last-resort prekeys; the ratchet deletes message keys
(`attacks/replay.py`).

## C. Formal verification

**12. What does ProVerif prove and what does it not?**
Symbolic (Dolev-Yao) model with perfect primitives, unbounded sessions: secrecy, agreement,
forward secrecy, hybrid secrecy, HNDL. It does not prove computational security bounds, side
channels, or the implementation's correctness — those are covered by tests, vectors and fuzzing.

**13. Your authentication query fails when X25519 is broken. Is the protocol broken?**
Not for confidentiality — secrecy still holds. It shows that Bob authenticates Alice through
`DH(IKdh_A, SPK_B)` only; with X25519 broken during the session, an attacker can impersonate Alice.
PQXDH has the same property. Fix: an ML-DSA transcript signature by Alice, which costs deniability.
I predicted this before writing the model, which shows the model tests something real.

**14. Why is your agreement query non-injective?**
The injective version did not terminate within 40 minutes. Injectivity (no replay) is enforced by
one-time prekeys and the replay cache, which are tested. I state this openly in `formal/RESULTS.md`.

**15. Why include queries that you *expect* to fail?**
Sanity: if "everything broken" or "classical vs. HNDL" were proved secure, the model would be
vacuous. Expected attacks show the attacker is strong enough.

## D. Ratchet

**16. Why a post-quantum ratchet if the handshake is already hybrid?**
Every key descends from the hybrid root key, so HNDL alone is already prevented. The PQ ratchet is
for *post-compromise security* against a quantum attacker: after a device theft, new DH keys do not
heal the session because a quantum attacker computes them; only a fresh ML-KEM secret does.

**17. Show me that.**
`tests/unit/test_ratchet_pcs.py`: a classical attacker with the stolen state loses access after 2
rounds whatever K is; a quantum attacker keeps access for K/2 rounds (2, 4, 6 for K = 4, 8, 12).
Bounded ProVerif model: the message after the KEM step is proved secret, earlier ones leak.

**18. Why K = 4?**
Benchmark `k_tradeoff`: healing cannot be faster than 2 rounds (the next sending key exists before
the theft), so K = 2 only costs 37 % more bandwidth. Above 4, each doubling halves the overhead and
doubles the window.

**19. How does yours differ from Signal's SPQR?**
SPQR spreads KEM keys and ciphertexts over many messages with erasure coding (the ML-KEM Braid), so
each message carries a small share and losses are tolerated. Ours sends them whole in every message
of a re-key chain: simpler to analyse, but ≈ 2.3 KB on those messages.

**20. Why does decryption work on a copy of the state?**
So a forged or corrupted message cannot desynchronise the session: state is committed only after the
AEAD verifies. Property test: 200 random bit flips are rejected and the original still decrypts.

## E. Implementation and testing

**21. How do you know the crypto libraries are used correctly?**
Thin wrappers with length checks, 100 % coverage, RFC vectors for X25519/HKDF/HMAC/AES-GCM/Ed25519,
and 85 NIST ACVP vectors for ML-KEM-768 and ML-DSA-65 (including invalid inputs that must fail).

**22. Python is not constant-time. Is that fatal?**
All secret-dependent arithmetic runs in liboqs and OpenSSL; Python only moves bytes and compares
secrets with `hmac.compare_digest` (enforced by a Semgrep rule). Recorded as a limitation (SR-35).

**23. How do you handle secrets in memory?**
Best effort: `bytearray` buffers overwritten after use (tested). Python can copy immutable `bytes`
anywhere; full erasure is impossible in Python — documented (T-27).

**24. What did testing actually find?**
Real bugs, each fixed with a regression test: rate limit disconnecting clients (1,000-message test),
per-target limit not wired in (exhaustion test), duplicate handshake on first reply (UI screenshot),
passphrase in URL and re-unlock (ZAP), a `wire.build` argument collision (mypy), a resource leak on
failed login (pytest warnings).

**25. How is the threat model kept in sync with the code?**
`tests/unit/test_threat_model_traceability.py` parses the tables: every requirement must trace to a
threat, have a planned test, and — when marked Done — cite evidence files that exist.

## F. Network, attacks, forensics

**26. What do the packet captures show?**
TLS 1.3, AES-256-GCM, key exchange X25519MLKEM768 (hybrid PQ TLS by default); zero plaintext or
usernames. Without TLS, content is still protected but the sender's name is visible — so TLS is
needed for metadata, not for content.

**27. Why pad messages?**
Without padding the ciphertext length reveals the plaintext length. Buckets 256/1,024/4,096/… hide
it within a bucket; the cost shows in the benchmarks.

**28. Your highest CVSS score is 9.1 Critical. Why is it accepted?**
F-01, first-contact impersonation by the relay. No cryptography can prove a key belongs to a person
without an out-of-band check. Safety numbers make it detectable; pinning blocks it after first
contact (both demonstrated). Same as Signal and WhatsApp.

**29. What did forensics teach you about methodology?**
Two things: (1) without positive controls "0 hits" proves nothing — the control exposed that SQLite
splits long values over overflow pages; (2) PQ secret keys contain their public keys (FIPS 203), so a
naive search raises false alarms. Both fixed and tested.

**30. Why did you not use Atheris?**
No wheel for Python 3.12 and the source build failed here; PROJECT-BRIEF.md allows Hypothesis instead.
200,000 mutated and random inputs over 10 parsers, zero unexpected exceptions.

## G. Governance and results

**31. When must X25519 and Ed25519 go?**
NIST IR 8547 (draft dates): quantum-vulnerable algorithms deprecated after 2030 and disallowed after
2035. PQ-Chat never relies on them alone; the transition plan in `docs/compliance.md` removes
classical mode by 2030 and the classical components by 2035.

**32. What is a CBOM and why produce one?**
A machine-readable inventory of cryptographic assets (CycloneDX 1.6). It makes the 2035 work list
explicit: every component with `nistQuantumSecurityLevel: 0` must be removed or wrapped by then.

**33. What is the cost of post-quantum security in one sentence?**
About 0.3 ms per handshake in CPU time but 67× the bundle payload and ≈ 4.5× the average message size
at K = 4 — post-quantum messaging is a bandwidth problem, not a CPU problem.

**34. What would you do with three more months?**
ML-DSA transcript signature for initiator authentication (F-02); erasure-coded re-keying like SPQR;
sealed sender to reduce relay metadata; key transparency to detect identity substitution; a
computational proof (e.g. CryptoVerif) for the hybrid combiner.
