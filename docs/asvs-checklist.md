# OWASP ASVS 5.0 — Level 2 checklist (Milestone 6)

**Scope:** the relay (`src/pqchat/server/`), the client's local web UI server (`src/pqchat/client/app.py`)
and its browser front end (`src/pqchat/client/static/`).
**Date:** 2026-11-09. **Status legend:** ✅ met · ◐ partly met / accepted · — not applicable.

> **Note on numbering.** Requirements are grouped by ASVS 5.0 chapter and paraphrased. Before citing
> individual requirement IDs (e.g. "V11.x.y") in the thesis, map each row to the exact ID in the
> official ASVS 5.0 document; the chapter assignments below were checked, the item numbers were not.

PQ-Chat has an unusual shape for ASVS: there are no passwords on the server, the "web app" is a
single-user UI on localhost, and the relay is untrusted by design. Several chapters therefore apply
only partly; the reason is given each time.

## V1 Encoding and Sanitization

| Requirement (paraphrased) | Status | Evidence |
|---|---|---|
| Output encoding appropriate to the context; untrusted data never interpreted as HTML/JS | ✅ | UI inserts all untrusted text with `textContent`; test `test_frontend_never_injects_html` forbids `innerHTML`, `eval`, inline handlers; browser E2E shows `<b>` rendered as text |
| No dynamic code execution from untrusted data | ✅ | No `eval`/`exec`/`pickle` (Semgrep rules `pqchat-no-eval-exec`, `pqchat-no-unsafe-deserialisation`) |
| Parameterised queries for the database | ✅ | `server/storage.py`: every SQL statement uses `?` placeholders |
| Safe deserialisation of structured data | ✅ | JSON only, schema-checked (`wire.parse`: exact key set, types, lengths, canonical base64url) |

## V2 Validation and Business Logic

| Requirement | Status | Evidence |
|---|---|---|
| Input validated against an allow-list / schema, server-side | ✅ | `wire.py` schemas; binary formats parsed by `protocol/encoding.py` before any crypto (SR-9); `tests/negative/test_parsing.py`, `tests/unit/test_relay.py` |
| Business limits and anti-automation (rate limits, quotas) | ✅ | Per-connection and per-target limits, 200 stored one-time prekeys per kind, 25 per upload (`tests/unit/test_ratelimit.py`) |
| Business-logic flows cannot be bypassed (order of steps) | ✅ | Relay accepts only `register`/`login` before authentication; challenge is single-use |

## V3 Web Frontend Security

| Requirement | Status | Evidence |
|---|---|---|
| Strict Content-Security-Policy without `unsafe-inline` / `unsafe-eval` | ✅ | `default-src 'none'; script-src 'self'; style-src 'self'; …; frame-ancestors 'none'` (`test_valid_request`) |
| `X-Content-Type-Options: nosniff`, referrer policy, anti-framing | ✅ | `SECURITY_HEADERS` in `client/app.py` |
| No third-party scripts or resources | ✅ | Test asserts no external URLs in `index.html` |
| Protection against cross-origin requests to the API (CSRF) and DNS rebinding | ✅ | Token header + Origin check + Host allow-list (`tests/negative/test_ui_security.py`) |
| Sensitive data not cached by the browser | ✅ | `Cache-Control: no-store` |

## V4 API and Web Service

| Requirement | Status | Evidence |
|---|---|---|
| Message size limits on HTTP and WebSocket | ✅ | 256 KiB envelope / frame limit (`test_oversized_frame_is_refused`); text ≤ 4,000 chars |
| WebSocket endpoints authenticate before privileged actions | ✅ | Challenge-response login with both identity keys (SR-21), `test_auth_signature_cannot_be_replayed` |
| API documentation / introspection not exposed | ✅ | `/docs`, `/redoc`, `/openapi.json` disabled (M0 tests) |

## V5 File Handling

| Requirement | Status | Evidence |
|---|---|---|
| No user-controlled file paths | ✅ | Static files served from an explicit two-name allow-list (`test_static_files_only_whitelisted`) |
| File uploads | — | PQ-Chat has no file uploads |

## V6 Authentication

| Requirement | Status | Evidence |
|---|---|---|
| Strong authentication of users to the server | ✅ | No passwords at the relay: signature over a fresh 32-byte challenge with Ed25519 **and** ML-DSA-65 |
| Replay-resistant authentication | ✅ | Challenge bound to the connection and single-use |
| Credential storage | ✅ | Relay stores only public identity keys. Client: private keys encrypted with Argon2id (64 MiB, t = 3, p = 4) + AES-256-GCM (SR-26) |
| Passphrase length rules | ◐ | Minimum 10, maximum 256 characters; no breached-password check (offline-only key store, ASM-5) |
| Account enumeration | ◐ | `fetch_bundle`/`send` reveal whether a name exists — inherent to a messenger directory; rate-limited |

## V7 Session Management

| Requirement | Status | Evidence |
|---|---|---|
| Session bound to the authenticated connection; new session replaces old | ✅ | Relay session = the authenticated WebSocket; a new login closes the previous connection |
| UI session token unpredictable and not in URLs sent to servers | ✅ | 256-bit `secrets.token_urlsafe`, delivered in the URL **fragment** (never sent over HTTP), moved to `sessionStorage`, removed from history |
| Idle / absolute timeouts | ◐ | UI token lives for the client process; acceptable for a single-user localhost UI. Documented |

## V8 Authorization

| Requirement | Status | Evidence |
|---|---|---|
| Users can only act on their own resources | ✅ | Upload prekeys only for the logged-in name; ack deletes only the caller's own messages (`test_send_deliver_ack_and_offline_queue`) |

## V9 / V10 Self-contained tokens, OAuth

— Not used.

## V11 Cryptography

| Requirement | Status | Evidence |
|---|---|---|
| Only approved, current algorithms; no custom crypto | ✅ | X25519, ML-KEM-768, Ed25519, ML-DSA-65, HKDF/HMAC-SHA-256, AES-256-GCM, Argon2id; Semgrep rule bans raw hazmat; ACVP/RFC vectors (M2) |
| Cryptographic inventory | ✅ | `docs/cbom.json` (M10) |
| Secure randomness | ✅ | `os.urandom`/`secrets`/library RNGs only (Semgrep `pqchat-no-random-module`) |
| Constant-time comparison of secrets | ✅ | `hmac.compare_digest` (Semgrep rule); Python not constant-time otherwise (documented limitation) |
| Key management: generation, rotation, deletion | ✅ | Signed prekeys rotate weekly, one-time prekeys deleted after use, ratchet keys deleted after use (M3/M5) |
| Post-quantum readiness | ✅ | Hybrid KEM and dual signatures throughout; TLS uses X25519MLKEM768 (M7) |

## V12 Secure Communication

| Requirement | Status | Evidence |
|---|---|---|
| TLS 1.2+ (here: 1.3 only) with strong suites, certificate validation | ✅ | `tests/unit/test_tls.py`; capture shows TLS 1.3, AES-256-GCM, X25519MLKEM768 |
| Internal traffic encrypted | ◐ | Client ↔ relay: TLS. UI ↔ client: HTTP on loopback only (no network exposure) |

## V13 Configuration

| Requirement | Status | Evidence |
|---|---|---|
| Dependencies pinned, scanned for known vulnerabilities | ✅ | `requirements/constraints.txt`, pip-audit in CI |
| Least privilege runtime | ✅ | Non-root user, read-only root FS, `cap_drop: ALL`, `no-new-privileges` |
| No debug features, server banners | ✅ | Server header off, docs off, log level warning |
| Secrets not in source or images | ✅ | No secrets in the repo; demo TLS key generated at start-up into a volume |

## V14 Data Protection

| Requirement | Status | Evidence |
|---|---|---|
| Sensitive data encrypted at rest | ✅ | Client key store and history encrypted (SR-26/27); relay holds only ciphertext (SR-19) |
| Data minimisation and retention limits | ✅ | Relay deletes on delivery, max 30 days (SR-20); `secure_delete=ON` in SQLite |
| No sensitive data in logs | ✅ | Redacting logger (`tests/unit/test_log_redaction.py`), relay logs no usernames |

## V15 Secure Coding and Architecture

| Requirement | Status | Evidence |
|---|---|---|
| Threat model and security requirements maintained | ✅ | `docs/threat-model.md`, machine-checked traceability |
| Static analysis in CI | ✅ | ruff (incl. bandit rules), mypy strict, Bandit, Semgrep with project rules |
| Defence against resource exhaustion | ✅ | Size limits, rate limits, skipped-key limit (1000), bounded rate-limiter memory |

## V16 Security Logging and Error Handling

| Requirement | Status | Evidence |
|---|---|---|
| Errors do not leak internals | ✅ | Generic error codes over the wire; all handshake failures reported as one `VerificationError` |
| Security events logged without sensitive data | ◐ | Authentication and dropped-message counters are logged without identifiers; no central log collection (out of scope) |

## V17 WebRTC

— Not used.

## Summary

All applicable Level 2 areas are met or partly met with a documented reason. Open items carried into
M8 (penetration test): run OWASP ZAP against the UI and relay; consider an idle timeout for the UI token.
