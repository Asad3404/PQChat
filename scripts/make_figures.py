"""Render the thesis figures into docs/figures/ (Milestone 12).

    .venv/bin/python scripts/make_figures.py

* architecture.svg/.png and key-schedule.svg/.png from the .dot sources (needs Graphviz `dot`);
* handshake-sequence.svg/.png drawn with matplotlib;
* result plots are produced by bench/run_bench.py (bench/results/*.png).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

FIG = Path(__file__).resolve().parents[1] / "docs" / "figures"


def graphviz() -> None:
    dot = shutil.which("dot")
    if dot is None:
        print("Graphviz 'dot' not found: skipping architecture and key-schedule figures")
        return
    for src in ("architecture", "key-schedule"):
        for fmt, extra in (("svg", []), ("png", ["-Gdpi=200"])):
            subprocess.run(  # noqa: S603 - fixed arguments, local Graphviz binary
                [dot, f"-T{fmt}", *extra, str(FIG / f"{src}.dot"), "-o", str(FIG / f"{src}.{fmt}")],
                check=True,
            )


def sequence() -> None:
    lanes = {"Alice": 0.0, "Relay (untrusted)": 1.0, "Bob": 2.0}
    steps = [
        (
            "Bob",
            "Relay (untrusted)",
            "upload IK + SPK, PQSPK, OPKs, PQOPKs\n(each signed with Ed25519 AND ML-DSA-65)",
            "#5b6470",
        ),
        ("Alice", "Relay (untrusted)", "fetch_bundle(bob)", "#5b6470"),
        ("Relay (untrusted)", "Alice", "bundle (one OPK + one PQOPK, then deleted)", "#5b6470"),
        (
            "Alice",
            "Alice",
            "verify both signatures on every prekey · refuse if no ML-KEM key\nDH1..DH4 (X25519) + Encaps(PQOPK) → SK → k_msg, RK₀",
            "#2f5d9e",
        ),
        (
            "Alice",
            "Relay (untrusted)",
            "initial message: header (mode, IK_A, EK_A, CT, ids)\n+ AES-GCM(k_msg, first ratchet message, AD ‖ header)",
            "#2f5d9e",
        ),
        ("Relay (untrusted)", "Bob", "same bytes (padded, opaque)", "#5b6470"),
        (
            "Bob",
            "Bob",
            "strict parse · policy · verify IK_A · Decaps(CT) · derive SK\ndecrypt · then delete used OPK/PQOPK",
            "#2f5d9e",
        ),
        ("Bob", "Relay (untrusted)", "reply on the double ratchet (new DH key)", "#2f5d9e"),
        ("Relay (untrusted)", "Alice", "reply", "#5b6470"),
        ("Alice", "Bob", "every K = 4 DH steps: ML-KEM re-key mixed into the root key", "#8a5a9e"),
    ]
    fig, ax = plt.subplots(figsize=(10, 7.2))
    top, gap = 0.95, 0.088
    for name, x in lanes.items():
        ax.text(x, 1.0, name, ha="center", va="bottom", fontsize=11, weight="bold")
        ax.plot([x, x], [0.02, 0.98], color="#c4c8ce", lw=1.2, zorder=0)
    for i, (src, dst, label, color) in enumerate(steps):
        y = top - (i + 0.5) * gap
        x0, x1 = lanes[src], lanes[dst]
        if src == dst:
            # A local step: the box is sized to its text so nothing spills over.
            x_text = min(max(x0, -0.05), 2.05)
            ax.text(
                x_text,
                y,
                label,
                ha="center",
                va="center",
                fontsize=7.6,
                color="#1b1c1f",
                bbox={"boxstyle": "round,pad=0.45", "fc": "#eef2f8", "ec": color, "lw": 0.8},
            )
        else:
            ax.annotate(
                "",
                xy=(x1, y),
                xytext=(x0, y),
                arrowprops={"arrowstyle": "-|>", "color": color, "lw": 1.3},
            )
            ax.text(
                (x0 + x1) / 2,
                y + 0.008,
                label,
                ha="center",
                va="bottom",
                fontsize=7.6,
                color="#1b1c1f",
            )
    ax.set_xlim(-0.55, 2.55)
    ax.set_ylim(0, 1.05)
    ax.axis("off")
    ax.set_title("PQ-Chat v1: first contact and first reply", fontsize=12, pad=18)
    fig.tight_layout()
    for fmt in ("svg", "png"):
        fig.savefig(FIG / f"handshake-sequence.{fmt}", dpi=200)
    plt.close(fig)


if __name__ == "__main__":
    graphviz()
    sequence()
    print(f"figures written to {FIG}")
