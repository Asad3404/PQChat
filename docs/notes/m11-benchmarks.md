# Milestone 11: benchmarks

**Reproduce everything:** `.venv/bin/python bench/run_bench.py --runs 1000` (≈ 10 s; needs the
`bench` extra: `pip install -e '.[bench]'`). All CSVs and plots land in `bench/results/`.

**Machine** (`bench/results/hardware.json`): Intel Xeon @ 2.30 GHz, 4 logical CPUs, 16 GB RAM,
Linux 6.18 x86_64, Python 3.12.3, liboqs 0.16.0, OpenSSL 3.0.13 (cloud VM — absolute numbers are only
comparable on the same machine; ratios between modes are the meaningful result).

## 1. Handshake latency (1,000 runs per mode)

| Mode | Alice median / p95 (ms) | Bob median / p95 (ms) | Total median / p95 (ms) |
|---|---|---|---|
| classical | 0.85 / 1.33 | 0.47 / 0.70 | 1.29 / 2.00 |
| hybrid | 1.06 / 1.17 | 0.55 / 0.61 | 1.62 / 2.51 |
| pq-only | 0.56 / 0.89 | 0.39 / 0.61 | 0.97 / 1.77 |

(The exact numbers in `handshake_summary.csv` vary by a few percent between runs.)

**Finding 1 — the post-quantum price is not CPU time.** Hybrid costs about **0.3 ms** more than
classical per handshake; `pq-only` is even *faster* than classical, because it skips four X25519
operations per side and ML-KEM / ML-DSA verification in liboqs (AVX2) are very fast. Alice's side
includes verifying every signature in the bundle (hybrid: 5 × Ed25519 + 5 × ML-DSA-65).

## 2. Sizes (`sizes.csv`, `sizes.png`)

| Mode | Bundle: crypto payload | First message: crypto payload | First message measured |
|---|---|---|---|
| classical | 320 B | 160 B | 6,969 B |
| hybrid | 21,313 B | 6,509 B | 8,061 B |
| pq-only | 14,247 B | 9,658 B | 11,333 B |

"Crypto payload" = keys, signatures and ciphertexts the mode actually needs (formula in
`run_bench.py::payload_sizes`). "Measured" = the real wire format, which always carries the full
hybrid identity (5.4 KB) and Alice's first ratchet message (with her ML-KEM announcement, ≈ 1.2 KB).

**Finding 2 — the price is bandwidth.** A hybrid bundle needs **67×** the payload of a classical one
(21.3 KB vs. 320 B), driven by ML-DSA-65 signatures (3,309 B each, one per prekey) and ML-KEM public
keys (1,184 B). Per handshake this is still small in absolute terms (one bundle download, one
≈ 8 KB first message).

## 3. Per-message cost (`messages.csv`, `message_overhead.png`)

Encrypt and decrypt take ≈ 0.03 ms each regardless of size. Size on the wire = padding bucket
(256 / 1,024 / 4,096 …) + 4-byte length + 16-byte tag + header. The table's 1,236-byte header is
the **worst case of a one-way stream**: if the peer never replies, the sender's ML-KEM public key is
never acknowledged and is repeated in every message (47 B plain header + 1,189 B announcement).

## 4. Cost of an ML-KEM re-key (`rekey.csv`, `rekey.png`, K = 4)

| Received message | Median receive time | Median size |
|---|---|---|
| same chain | 0.022 ms | 1,512 B |
| same chain, repeats ML-KEM ciphertext | 0.023 ms | 2,009 B |
| new DH chain | 0.14 ms | 1,512 B |
| new DH chain + ML-KEM step | 0.19–0.25 ms | 2,009 B |

A DH ratchet step costs ≈ 0.12 ms; adding the ML-KEM step (decapsulation, a fresh own KEM key pair,
encapsulation for the next chain) adds ≈ 0.05–0.1 ms. Again cheap in time, expensive in bytes.

## 5. The key trade-off: re-key interval K (`k_tradeoff.csv`, `k_tradeoff.png`)

Healing is **measured** with the quantum shadow attacker from `tests/unit/test_ratchet_pcs.py`.

| K | Rounds a quantum attacker still reads after a theft | Messages with KEM public key | with KEM ciphertext | Mean message size |
|---|---|---|---|---|
| 2 | 2 | 50 % | 99 % | 1,993 B |
| **4 (default)** | **2** | 50 % | 50 % | **1,458 B** |
| 8 | 4 | 26 % | 25 % | 899 B |
| 16 | 8 | 13 % | 12 % | 609 B |
| 32 | 16 | 7 % | 6 % | 472 B |
| *no PQ ratchet* | *never heals* | — | — | *323 B* |

**Finding 3 — K = 4 is the sweet spot.** Healing cannot be faster than 2 rounds (Bob's next sending
key exists before the theft), so K = 2 only adds 37 % bandwidth. Above 4, each doubling of K halves
the PQ overhead and doubles the attacker's window. This curve is exactly the problem Signal's SPQR
solves with the erasure-coded ML-KEM Braid (spreading ≈ 2.3 KB over many messages); our simplified
design makes the cost explicit.

## 6. Memory (`memory.csv`)

Peak Python heap per complete handshake: classical 64 KiB, hybrid 68 KiB, pq-only 94 KiB
(pq-only creates the ML-DSA transcript signature). C allocations inside liboqs and OpenSSL are not
visible to `tracemalloc`; the process's maximum RSS for the whole benchmark was ≈ 127 MiB.

## 7. Threats to validity

* Shared cloud VM: other tenants add noise (visible in p95). Ratios matter more than absolutes.
* Python overhead dominates small operations; a C or Rust implementation would be faster across
  the board, but the ranking of modes would not change because the primitives already run in C.
* `pq-only` still uses the X25519 double ratchet after the handshake (documented in the protocol
  spec); its handshake numbers are the meaningful part.
* No network latency is included: sizes are reported separately so they can be combined with any
  link model.
