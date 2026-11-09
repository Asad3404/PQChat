# Milestone 7: network hardening and metadata-leakage analysis

**Status:** implemented (review after M12). Evidence in `evidence/m7/`.

## 1. What was added

| Control | Requirement | Where | Test / evidence |
|---|---|---|---|
| TLS 1.3 only on the relay (min = max = 1.3), certificate verification and hostname check on the client | SR-23 | `server/tls.py`, `client/tls.py` | `tests/unit/test_tls.py` (TLS 1.2 refused, foreign CA refused); capture below |
| Padding to 256 / 1024 / 4096 / 16384 / 65536-byte buckets (ISO/IEC 7816-4) | SR-24 | `protocol/padding.py`, `protocol/session.py` | `tests/property/test_padding.py` |
| Rate limits per connection (50/s, burst 200) and per requester→target bundle fetch | SR-22 | `server/ratelimit.py`, `server/app.py` | `tests/unit/test_ratelimit.py` |
| Prekey-exhaustion protection: per-*target* bundle budget (20, refilling 12/min) shared by all requesters; client tops up below 20 one-time prekeys | SR-22, T-16 | `server/app.py`, `client/core.py` | `test_prekey_exhaustion_is_capped`: 3 attacker accounts × 10 fetches leave ≥ 5 of 25 prekeys |
| Frame size limit (256 KiB) and strict envelope parsing | SR-9 | `wire.py`, uvicorn `ws_max_size` | `tests/unit/test_relay.py` |
| Demo CA for Docker (relay certificate, CA key never written to disk) | — | `server/devcerts.py` | `docker compose up` |

**Two bugs found while testing (both fixed):**

1. The first per-connection limit (burst 60, 20/s) *disconnected* clients during ordinary bursty use;
   found by the 1,000-message test. Now: higher limit, a rejected envelope gets a `rate_limited`
   error, only 100 violations end the connection; the client fails pending requests on such errors.
2. The per-target limit was written but **not wired in** (an edit missed after reformatting); found by
   the exhaustion test, which reported zero rejections.

## 2. Packet captures

Both captured with `tcpdump` during real runs; analysed with `tshark` and a byte search.

### 2.1 Docker Compose, TLS on — `evidence/m7/tls-session.pcap`

Two browsers chatting through the relay (the M6 end-to-end run, `scripts/e2e_browser.mjs`).

| Check | Result |
|---|---|
| Packets | 147 |
| Negotiated TLS version (ServerHello `supported_versions`) | `0x0304` = **TLS 1.3**, both connections |
| Cipher suite | `0x1302` = TLS_AES_256_GCM_SHA384 |
| Key exchange group | `4588` = `0x11EC` = **X25519MLKEM768** (hybrid post-quantum TLS, chosen by OpenSSL in the image by default) |
| Message text, usernames, JSON field names found in the bytes | **0** for every marker |

Note: the TLS certificate itself is classical (ECDSA P-256). Transport *confidentiality* is therefore
hybrid post-quantum, transport *authentication* is not. Message security never depends on TLS.

### 2.2 In-process relay, TLS off — `evidence/m7/no-tls-e2e-only.pcap`

Deliberately without TLS, to see what the end-to-end layer alone protects (test `test_chat_persistence_and_restart`).

| Marker | Hits | Meaning |
|---|---|---|
| `hi bob`, `reply 0`, `after restart`, `still here` | 0 | Message content is protected by the E2E layer alone |
| `"from":"alice"` | 2 | **Metadata leak:** relay → client frames name the sender |
| `"type":"send"`, `"to":"bob"` | 0 | Only because RFC 6455 *masks* client → server frames; masking is **not** encryption (the key is in the frame) |

## 3. Metadata-leakage analysis

What each observer learns, after all controls (A1 = network, A2 = relay):

| Metadata | A1 without TLS | A1 with TLS 1.3 | A2 (relay) | Mitigation / status |
|---|---|---|---|---|
| Message content | no | no | no | E2E encryption (M3, M5) |
| Exact message length | bucket only | bucket only (+ TLS record framing) | bucket only | Padding (SR-24) |
| Sender and recipient usernames | **yes** | no | **yes** | TLS hides from A1; relay sees them — accepted (T-15) |
| Timing and frequency of messages | yes | yes | yes | Not mitigated (traffic analysis out of scope) |
| Who is online, client IP addresses | yes | yes | yes | Not mitigated; relay logs no IPs or usernames (SR-25) |
| Social graph over time | yes | partly (IPs) | **yes** | Accepted residual risk T-15 (score 12); future work: sealed sender |
| That a message is a handshake (`init`) vs. a ratchet message | yes | no | **yes** | Size also reveals it (≈ 9–10 KB vs. ≤ 1–2 KB); accepted |
| Which messages carry an ML-KEM re-key | via size | via size | via size | ≈ +1.1–2.3 KB per re-key message; SPQR's erasure-coded braid would smooth this (documented simplification) |
| Prekey consumption (how many people start chats with Bob) | no | no | **yes** | Inherent in prekey servers |

**Conclusion.** Content is protected end to end and the transport adds hybrid post-quantum
confidentiality; the remaining leaks are *who talks to whom and when*, visible to the relay by design
and to a network observer only as IP-level timing. This matches the accepted risk T-15 in the threat
model; closing it requires sealed-sender style designs or mixnets, which are outside this project.
