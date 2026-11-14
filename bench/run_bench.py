"""PQ-Chat benchmarks (Milestone 11). One command reproduces every CSV and plot:

    .venv/bin/python bench/run_bench.py --runs 1000

Outputs in bench/results/:
  hardware.json             machine, OS, Python, library versions, date
  handshake_raw.csv         one row per run and mode (wall-clock and CPU time, sizes)
  handshake_summary.csv     median and p95 per mode and side
  sizes.csv                 bundle / first message, wire format vs. cryptographic payload
  messages.csv              per-message overhead for several plaintext sizes
  rekey.csv                 receive cost: same chain vs. new DH chain vs. new chain + ML-KEM
  memory.csv                peak Python heap per handshake (tracemalloc)
  k_tradeoff.csv            re-key interval K: measured quantum healing vs. mean message size
  *.png                     plots of the above

Timing uses time.perf_counter (wall clock) and time.process_time (CPU) around each operation;
garbage collection is disabled while timing. Results are only comparable on the same machine.
"""

from __future__ import annotations

import argparse
import datetime
import gc
import json
import platform
import resource
import ssl
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from pqchat.protocol.bundle import IdentityKeys, PrekeyStore  # noqa: E402
from pqchat.protocol.modes import Mode, Policy  # noqa: E402
from pqchat.protocol.ratchet import parse_message  # noqa: E402
from pqchat.protocol.session import Session  # noqa: E402

RESULTS = ROOT / "bench" / "results"
MODES = [Mode.CLASSICAL, Mode.HYBRID, Mode.PQ_ONLY]
POLICY = Policy(allow_classical=True, allow_pq_only=True)
COLORS = {"classical": "#7a7f87", "hybrid": "#2f5d9e", "pq_only": "#8a5a9e"}

# Sizes in bytes of the cryptographic objects (RFC 7748/8032, FIPS 203/204).
X_PK, ED_PK, ED_SIG = 32, 32, 64
KEM_PK, KEM_CT = 1184, 1088
DSA_PK, DSA_SIG = 1952, 3309


def hardware() -> dict[str, Any]:
    import oqs

    info: dict[str, Any] = {
        "date_utc": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "liboqs": oqs.oqs_version(),
        "openssl": ssl.OPENSSL_VERSION,
    }
    try:
        cpu = Path("/proc/cpuinfo").read_text()
        info["cpu"] = next(
            line.split(":", 1)[1].strip()
            for line in cpu.splitlines()
            if line.startswith("model name")
        )
        info["logical_cpus"] = cpu.count("processor\t:")
        mem = Path("/proc/meminfo").read_text().splitlines()[0]
        info["memory_kib"] = int(mem.split()[1])
    except (OSError, StopIteration):
        info["cpu"] = platform.processor()
    return info


def timed(fn: Callable[[], Any]) -> tuple[Any, float, float]:
    w0, c0 = time.perf_counter(), time.process_time()
    out = fn()
    return out, (time.perf_counter() - w0) * 1e3, (time.process_time() - c0) * 1e3


def fresh_bob(now: int) -> PrekeyStore:
    bob = PrekeyStore(IdentityKeys.generate())
    bob.rotate_signed(now)
    bob.add_one_time(1, now)
    return bob


def bench_handshakes(runs: int) -> pd.DataFrame:
    now = int(time.time())
    alice = IdentityKeys.generate()
    rows = []
    for mode in MODES:
        for i in range(runs):
            bob = fresh_bob(now)
            bundle = bob.bundle()
            gc.disable()
            (_, first), a_ms, a_cpu = timed(
                lambda bundle=bundle, mode=mode: Session.initiate(
                    alice, bundle, b"hello", mode=mode, policy=POLICY, now=now
                )
            )
            _, b_ms, b_cpu = timed(
                lambda bob=bob, first=first: Session.accept(bob, first, policy=POLICY, now=now)
            )
            gc.enable()
            rows.append(
                {
                    "mode": mode.name.lower(),
                    "run": i,
                    "alice_ms": a_ms,
                    "bob_ms": b_ms,
                    "total_ms": a_ms + b_ms,
                    "alice_cpu_ms": a_cpu,
                    "bob_cpu_ms": b_cpu,
                    "bundle_bytes": len(bundle.encode()),
                    "first_message_bytes": len(first),
                }
            )
    return pd.DataFrame(rows)


def p95(s: pd.Series) -> float:
    return float(s.quantile(0.95))


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    out = []
    for mode, g in df.groupby("mode", sort=False):
        for col in ("alice_ms", "bob_ms", "total_ms", "alice_cpu_ms", "bob_cpu_ms"):
            out.append(
                {
                    "mode": mode,
                    "metric": col,
                    "median": round(float(g[col].median()), 4),
                    "p95": round(p95(g[col]), 4),
                    "runs": len(g),
                }
            )
    return pd.DataFrame(out)


def payload_sizes() -> pd.DataFrame:
    """What each mode cryptographically needs, versus the actual (hybrid-capable) wire format."""
    identity = {
        "classical": ED_PK + X_PK + ED_SIG,
        "hybrid": ED_PK + DSA_PK + X_PK + ED_SIG + DSA_SIG,
        "pq_only": DSA_PK + DSA_SIG,
    }
    prekeys = {  # SPK + OPK for DH modes, PQSPK + PQOPK for KEM modes, each with its signatures
        "classical": 2 * (X_PK + ED_SIG),
        "hybrid": 2 * (X_PK + ED_SIG + DSA_SIG) + 2 * (KEM_PK + ED_SIG + DSA_SIG),
        "pq_only": 2 * (KEM_PK + DSA_SIG),
    }
    first = {  # identity of Alice + ephemeral + ciphertext (+ transcript signature in pq-only)
        "classical": identity["classical"] + X_PK,
        "hybrid": identity["hybrid"] + X_PK + KEM_CT,
        "pq_only": identity["pq_only"] + KEM_CT + DSA_SIG,
    }
    return pd.DataFrame(
        [
            {
                "mode": m,
                "bundle_payload_bytes": identity[m] + prekeys[m],
                "first_message_payload_bytes": first[m],
            }
            for m in identity
        ]
    )


def bench_messages(runs: int) -> pd.DataFrame:
    from tests.conftest import make_pair

    alice, bob = make_pair()
    rows = []
    for size in (1, 100, 255, 1000, 4000):
        text = b"x" * size
        enc_ms, dec_ms, wire = [], [], 0
        for _ in range(runs // 10):
            m, ms, _ = timed(lambda: alice.encrypt(text))  # noqa: B023
            _, ms2, _ = timed(lambda: bob.decrypt(m))  # noqa: B023
            enc_ms.append(ms)
            dec_ms.append(ms2)
            wire = len(m)
        header, _, _ = parse_message(m)
        rows.append(
            {
                "plaintext_bytes": size,
                "wire_bytes": wire,
                "overhead_bytes": wire - size,
                "header_bytes": len(header.encode()),
                "encrypt_ms_median": statistics.median(enc_ms),
                "encrypt_ms_p95": p95(pd.Series(enc_ms)),
                "decrypt_ms_median": statistics.median(dec_ms),
                "decrypt_ms_p95": p95(pd.Series(dec_ms)),
            }
        )
    return pd.DataFrame(rows)


def bench_rekey(runs: int) -> pd.DataFrame:
    """Receive cost by message type, from a long alternating conversation with K = 4."""
    from tests.conftest import make_pair

    alice, bob = make_pair(interval=4)
    kinds = [
        "same chain",
        "same chain, repeats ML-KEM ciphertext",
        "new DH chain",
        "new DH chain + ML-KEM",
    ]
    samples: dict[str, list[float]] = {k: [] for k in kinds}
    sizes: dict[str, list[int]] = {k: [] for k in kinds}
    turn = 0
    while min(len(v) for v in samples.values()) < runs // 4:
        sender, receiver = (alice, bob) if turn % 2 == 0 else (bob, alice)
        for j in range(2):
            m = sender.encrypt(b"benchmark message")
            h, _, _ = parse_message(m)
            if j == 0:
                kind = "new DH chain + ML-KEM" if h.kem_ct else "new DH chain"
            else:
                kind = "same chain, repeats ML-KEM ciphertext" if h.kem_ct else "same chain"
            _, ms, _ = timed(lambda: receiver.decrypt(m))  # noqa: B023
            samples[kind].append(ms)
            sizes[kind].append(len(m))
        turn += 1
    return pd.DataFrame(
        [
            {
                "message_type": k,
                "receive_ms_median": statistics.median(samples[k]),
                "receive_ms_p95": p95(pd.Series(samples[k])),
                "samples": len(samples[k]),
                "wire_bytes_median": int(statistics.median(sizes[k])),
            }
            for k in kinds
        ]
    )


def bench_k_tradeoff() -> pd.DataFrame:
    """Healing speed vs. bandwidth for the PQ re-key interval K.

    Healing is *measured* with the quantum shadow attacker of tests/unit/test_ratchet_pcs.py
    (a copy of Bob's state plus every future X25519 private key, but no ML-KEM keys).
    """
    from tests.conftest import make_pair
    from tests.unit.test_ratchet_pcs import _quantum_shadow_run

    rows = []
    for k in (2, 4, 8, 16, 32):
        readable = _quantum_shadow_run(k, rounds=max(12, k))
        heal = readable.index(False) if False in readable else len(readable)
        a, b = make_pair(interval=k)
        total = with_pub = with_ct = 0
        nbytes = 0
        for turn in range(200):
            snd, rcv = (a, b) if turn % 2 == 0 else (b, a)
            for _ in range(3):  # three messages per turn
                m = snd.encrypt(b"x")
                h, _, _ = parse_message(m)
                rcv.decrypt(m)
                total += 1
                with_pub += h.kem_pub is not None
                with_ct += h.kem_ct is not None
                nbytes += len(m)
        rows.append(
            {
                "K": k,
                "quantum_attacker_rounds_after_theft": heal,
                "share_with_kem_public_key": round(with_pub / total, 3),
                "share_with_kem_ciphertext": round(with_ct / total, 3),
                "mean_message_bytes": round(nbytes / total),
                "plain_message_bytes": 323,
            }
        )
    return pd.DataFrame(rows)


def bench_memory() -> pd.DataFrame:
    now = int(time.time())
    alice = IdentityKeys.generate()
    rows = []
    for mode in MODES:
        bob = fresh_bob(now)
        bundle = bob.bundle()
        tracemalloc.start()
        _, first = Session.initiate(alice, bundle, b"hello", mode=mode, policy=POLICY, now=now)
        Session.accept(bob, first, policy=POLICY, now=now)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append(
            {
                "mode": mode.name.lower(),
                "python_heap_peak_kib": round(peak / 1024, 1),
                "note": "Python allocations only; liboqs/OpenSSL C allocations are not traced",
            }
        )
    rows.append(
        {
            "mode": "process",
            "python_heap_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "note": "ru_maxrss in KiB for the whole benchmark process",
        }
    )
    return pd.DataFrame(rows)


def plot_k(kt: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(
        kt["quantum_attacker_rounds_after_theft"],
        kt["mean_message_bytes"],
        marker="o",
        color="#2f5d9e",
    )
    for _, r in kt.iterrows():
        ax.annotate(
            f"K={int(r['K'])}",
            (r["quantum_attacker_rounds_after_theft"], r["mean_message_bytes"]),
            xytext=(6, 4),
            textcoords="offset points",
            fontsize=8,
        )
    ax.axhline(323, color="#7a7f87", linestyle="--", linewidth=1)
    ax.text(
        kt["quantum_attacker_rounds_after_theft"].max(),
        323,
        "plain message, no PQ ratchet (323 B)",
        ha="right",
        va="bottom",
        fontsize=8,
        color="#7a7f87",
    )
    ax.set_xlabel("rounds a quantum attacker keeps reading after a device theft (lower is better)")
    ax.set_ylabel("mean message size on the wire (bytes)")
    ax.set_title("ML-KEM re-key interval K: healing speed vs. bandwidth")
    fig.tight_layout()
    fig.savefig(RESULTS / "k_tradeoff.png", dpi=200)
    plt.close(fig)


def plots(raw: pd.DataFrame, sizes: pd.DataFrame, msgs: pd.DataFrame, rekey: pd.DataFrame) -> None:
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    modes = ["classical", "hybrid", "pq_only"]

    fig, ax = plt.subplots(figsize=(7, 4))
    data = [raw[raw["mode"] == m]["total_ms"] for m in modes]
    bp = ax.boxplot(data, tick_labels=modes, showfliers=False, patch_artist=True, widths=0.5)
    for patch, m in zip(bp["boxes"], modes, strict=True):
        patch.set_facecolor(COLORS[m])
        patch.set_alpha(0.75)
    for i, d in enumerate(data, start=1):
        ax.annotate(
            f"median {d.median():.2f} ms\np95 {d.quantile(0.95):.2f} ms",
            (i, d.quantile(0.95)),
            xytext=(0, 8),
            textcoords="offset points",
            ha="center",
            fontsize=8,
        )
    ax.set_ylabel("handshake time, Alice + Bob (ms)")
    ax.set_title(f"Handshake latency per mode ({len(data[0])} runs each)")
    fig.tight_layout()
    fig.savefig(RESULTS / "handshake_time.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    first = raw.groupby("mode")["first_message_bytes"].median().reindex(modes)
    payload = sizes.set_index("mode").reindex(modes)
    x = range(len(modes))
    ax.bar(
        [i - 0.2 for i in x],
        payload["bundle_payload_bytes"] / 1024,
        0.4,
        label="bundle (crypto payload)",
        color="#9fb6d6",
    )
    ax.bar(
        [i + 0.2 for i in x], first / 1024, 0.4, label="first message (measured)", color="#2f5d9e"
    )
    for i, m in enumerate(modes):
        ax.text(
            i - 0.2,
            payload.loc[m, "bundle_payload_bytes"] / 1024,
            f"{payload.loc[m, 'bundle_payload_bytes'] / 1024:.1f}",
            ha="center",
            va="bottom",
            fontsize=8,
        )
        ax.text(
            i + 0.2, first[m] / 1024, f"{first[m] / 1024:.1f}", ha="center", va="bottom", fontsize=8
        )
    ax.set_xticks(list(x), modes)
    ax.set_ylabel("KiB")
    ax.set_title("What each mode puts on the wire")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(RESULTS / "sizes.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(
        msgs["plaintext_bytes"].astype(str),
        msgs["wire_bytes"],
        color="#2f5d9e",
        label="on the wire",
    )
    ax.bar(
        msgs["plaintext_bytes"].astype(str),
        msgs["plaintext_bytes"],
        color="#9fb6d6",
        label="plaintext",
    )
    ax.set_xlabel("plaintext size (bytes)")
    ax.set_ylabel("bytes")
    ax.set_yscale("log")
    ax.set_title("Per-message size: padding buckets plus a 47-byte header")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(RESULTS / "message_overhead.png", dpi=200)
    plt.close(fig)

    fig, ax1 = plt.subplots(figsize=(8, 4.5))
    labels = [t.replace(", ", ",\n").replace(" + ", "\n+ ") for t in rekey["message_type"]]
    ax1.bar(labels, rekey["receive_ms_median"], color=["#c9d6ea", "#9fb6d6", "#5f86bf", "#2f5d9e"])
    for i, r in rekey.reset_index().iterrows():
        ax1.text(
            i,
            r["receive_ms_median"],
            f"{r['receive_ms_median']:.3f} ms\n{r['wire_bytes_median']} B",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    ax1.set_ylabel("median receive time (ms)")
    ax1.set_title("Cost of an ML-KEM re-key step (K = 4)")
    fig.tight_layout()
    fig.savefig(RESULTS / "rekey.png", dpi=200)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1000)
    args = ap.parse_args()
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "hardware.json").write_text(json.dumps(hardware(), indent=2))
    raw = bench_handshakes(args.runs)
    raw.to_csv(RESULTS / "handshake_raw.csv", index=False)
    summary = summarise(raw)
    summary.to_csv(RESULTS / "handshake_summary.csv", index=False)
    sizes = payload_sizes().merge(
        raw.groupby("mode")[["bundle_bytes", "first_message_bytes"]]
        .median()
        .reset_index()
        .rename(
            columns={
                "bundle_bytes": "bundle_wire_bytes",
                "first_message_bytes": "first_message_wire_bytes",
            }
        ),
        on="mode",
    )
    sizes.to_csv(RESULTS / "sizes.csv", index=False)
    msgs = bench_messages(args.runs)
    msgs.to_csv(RESULTS / "messages.csv", index=False)
    rekey = bench_rekey(args.runs)
    rekey.to_csv(RESULTS / "rekey.csv", index=False)
    bench_memory().to_csv(RESULTS / "memory.csv", index=False)
    kt = bench_k_tradeoff()
    kt.to_csv(RESULTS / "k_tradeoff.csv", index=False)
    plot_k(kt)
    plots(raw, sizes, msgs, rekey)
    print(summary[summary["metric"] == "total_ms"].to_string(index=False))
    print(sizes.to_string(index=False))
    print(rekey.to_string(index=False))
    print(kt.to_string(index=False))


if __name__ == "__main__":
    main()
