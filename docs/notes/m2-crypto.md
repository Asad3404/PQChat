# Design note — Milestone 2: crypto wrappers

**Status:** implemented (review after M12, as agreed on 2026-11-06)

## Goal

One thin, typed module per primitive in `src/pqchat/crypto/`, so protocol code never touches
liboqs or pyca directly. "Done when": all vector tests pass and `crypto/` has 100 % coverage.

## Modules

| Module | Wraps | API (simplified) | Notes |
|---|---|---|---|
| `errors.py` | – | `CryptoError` | One opaque error type. Messages never contain key material or say *which* check failed in a way that helps an attacker. |
| `labels.py` | – | constants | Single registry of every HKDF `info` / HMAC / signature label (SR-16). A test checks they are unique and start with `PQChat-v1`. |
| `zeroize.py` | – | `wipe(bytearray)` | Best-effort overwrite (SR-15). See limitations. |
| `dh.py` | pyca X25519 | `X25519KeyPair.generate()`, `.dh(peer_pub) -> bytearray` | Rejects wrong-length public keys and all-zero (low-order) results. |
| `kem.py` | liboqs ML-KEM-768 | `MLKEMKeyPair.generate()`, `encapsulate(pk) -> (ct, ss)`, `.decapsulate(ct) -> ss` | Exact length checks *before* liboqs is called. liboqs also performs the FIPS 203 encapsulation-key modulus check (verified with NIST vectors). |
| `sig.py` | pyca Ed25519, liboqs ML-DSA-65 | `HybridSigningKey.generate()`, `.sign(label, msg)`, `verify_hybrid(...)` | Domain separation: the signed message is `label ‖ msg`; for ML-DSA the label is also passed as the FIPS 204 *context string*. `verify_hybrid` evaluates **both** signatures and returns true only if both pass (SR-5). |
| `kdf.py` | pyca HKDF / HMAC | `hkdf(ikm, salt, info, length)`, `hmac_sha256(key, data)`, `verify_hmac(...)` | Output is a `bytearray` so callers can wipe it. `verify_hmac` uses `hmac.compare_digest` (SR-3). |
| `aead.py` | pyca AESGCM | `seal(key, nonce, pt, ad)`, `open_(key, nonce, ct, ad)` | 32-byte key and 12-byte nonce enforced. A failed tag raises `CryptoError`. |
| `keystore_crypto.py` | argon2-cffi + AESGCM | `encrypt_keystore(passphrase, plaintext)`, `decrypt_keystore(passphrase, blob)` | Argon2id m = 64 MiB, t = 3, p = 4 (RFC 9106 second recommendation), random 16-byte salt. The header (magic, version, parameters, salt, nonce) is the AEAD associated data, so tampering with parameters is detected; parameters below the minimum are refused before Argon2 runs. |
| `pqchat/logsafe.py` | stdlib logging | `RedactingFilter`, `get_logger(name)` | Replaces `bytes`/`bytearray` arguments and long hex/base64 strings with `<redacted N bytes>` (SR-25). |

## Nonces

`aead.seal` takes an explicit nonce. The protocol (M3, M5) uses each AES key for **exactly one**
message (every message key is fresh from a KDF), so a fixed or derived nonce is safe there. The
key store uses a random nonce with a fresh key per save (fresh salt), so nonce reuse cannot happen.

## Vectors

| Primitive | Source | Count |
|---|---|---|
| X25519 | RFC 7748 §5.2 and §6.1 | 3 |
| HKDF-SHA256 | RFC 5869 test cases 1–3 | 3 |
| HMAC-SHA256 | RFC 4231 test cases 1, 2 | 2 |
| AES-256-GCM | McGrew–Viega GCM spec test cases 13–16 (as used by NIST CAVP) | 4 |
| ML-KEM-768 | NIST ACVP FIPS 203: keyGen (25), encapsulation→decaps (25), decapsulation incl. invalid ciphertexts (10), encapsulation-key check (10) | 70 |
| ML-DSA-65 | NIST ACVP FIPS 204: sigVer, external/pure interface with context (15, of which 12 must fail) | 15 |
| Ed25519 | RFC 8032 §7.1 test 1 and 2 | 2 |

The ACVP subset lives in `tests/vectors/data/acvp_pq.json`; `tests/vectors/extract_acvp.py`
regenerates it from NIST's files.

## Limitations (record in thesis)

* **Zeroisation is best effort.** `bytes` objects are immutable and may be copied by the
  interpreter, the garbage collector or the C libraries; only our own `bytearray` buffers can be
  overwritten, and pyca returns `bytes` that we copy into `bytearray` and drop. (SR-15, T-27)
* **Python is not constant time.** All secret-dependent arithmetic happens in liboqs / OpenSSL;
  Python code only moves secret bytes around and compares them with `hmac.compare_digest`. (SR-35)
