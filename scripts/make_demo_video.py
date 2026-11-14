"""Assemble the PQ-Chat demo video from a recording made by scripts/record_demo.mjs.

    .venv/bin/python scripts/make_demo_video.py <recording-dir> <relay_view.txt> <out.mp4>

relay_view.txt is the real database view shown on one card; produce it after the chat with
    scripts/relay_view.sh "post-quantum message" "brand-new key" > <recording-dir>/relay_view.txt

Structure: title card -> architecture card -> live recording (Alice | Bob side by side, captions
burned in at the recorded times) -> "what the relay sees" card (real database output) ->
"proven and tested" card -> closing card. Needs ffmpeg with libfreetype (drawtext).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.image as mpimg
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parents[1]
W, H, FPS = 1920, 1080, 30
INK, SUB, BRAND, PANE, RED = "#1b1c1f", "#5b6470", "#2f5d9e", "#f4f5f7", "#b3261e"
FONT = "/usr/share/fonts/opentype/inter/Inter-Regular.otf"
FONT_BOLD = "/usr/share/fonts/opentype/inter/Inter-SemiBold.otf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

for f in (FONT, FONT_BOLD):
    if Path(f).exists():
        font_manager.fontManager.addfont(f)
plt.rcParams["font.family"] = "Inter" if Path(FONT).exists() else "DejaVu Sans"


def run(*args: str) -> None:
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], check=True)  # noqa: S603, S607


def canvas() -> tuple[plt.Figure, plt.Axes]:
    fig = plt.figure(figsize=(W / 100, H / 100), dpi=100)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    fig.patch.set_facecolor("white")
    return fig, ax


def save(fig: plt.Figure, path: Path) -> Path:
    fig.savefig(path, dpi=100, facecolor=fig.get_facecolor())
    plt.close(fig)
    return path


def title_card(path: Path) -> Path:
    fig, ax = canvas()
    ax.text(160, 300, "PQ-Chat", fontsize=96, weight="bold", color=INK)
    ax.text(
        160,
        400,
        "An end-to-end encrypted messenger built to survive a quantum computer",
        fontsize=34,
        color=SUB,
    )
    items = [
        ("Hybrid handshake", "X25519 + ML-KEM-768 (FIPS 203): secure if either one holds"),
        ("Dual signatures", "every key signed with Ed25519 AND ML-DSA-65 (FIPS 204)"),
        ("Self-healing chats", "double ratchet with periodic ML-KEM re-keying"),
        ("Untrusted relay", "the server only ever sees public keys and ciphertext"),
    ]
    for i, (head, body) in enumerate(items):
        y = 560 + i * 100
        ax.add_patch(plt.Rectangle((160, y - 34), 10, 52, color=BRAND))
        ax.text(200, y, head, fontsize=30, weight="bold", color=INK, va="center")
        ax.text(560, y, body, fontsize=28, color=SUB, va="center")
    ax.text(
        160,
        1000,
        "Live demo · MS Cybersecurity capstone · synthetic accounts only",
        fontsize=22,
        color=SUB,
    )
    return save(fig, path)


def architecture_card(path: Path) -> Path:
    fig, ax = canvas()
    ax.text(120, 120, "How it fits together", fontsize=52, weight="bold", color=INK)
    ax.text(
        120,
        190,
        "Keys never leave a device. The relay stores and forwards opaque, padded ciphertext over TLS 1.3.",
        fontsize=26,
        color=SUB,
    )
    img = mpimg.imread(ROOT / "docs" / "figures" / "architecture.png")
    h, w = img.shape[:2]
    scale = min(1680 / w, 760 / h)
    x0, y0 = (W - w * scale) / 2, 260
    ax.imshow(img, extent=(x0, x0 + w * scale, y0 + h * scale, y0))
    return save(fig, path)


def relay_card(path: Path, relay_view: str) -> Path:
    fig, ax = canvas()
    ax.text(120, 120, "What the relay actually stores", fontsize=52, weight="bold", color=INK)
    ax.text(
        120,
        190,
        "Real output from the relay's database, taken right after the chat you just watched.",
        fontsize=26,
        color=SUB,
    )
    ax.add_patch(plt.Rectangle((120, 240), 1680, 600, color="#16181c"))
    for i, line in enumerate(relay_view.strip().splitlines()):
        color = "#8fb3e8" if line.startswith(("$", ">")) else "#cfd3da"
        ax.text(
            160,
            290 + i * 42,
            line,
            fontsize=22,
            color=color,
            family="DejaVu Sans Mono",
            va="center",
        )
    notes = [
        "No message text anywhere in the file, and delivered messages are deleted.",
        "Bob has 49 one-time prekeys left: Alice's handshake used exactly one, which the relay deleted.",
        "Alice still has 50: Bob answered on the ratchet without a second handshake.",
    ]
    for i, n in enumerate(notes):
        ax.text(120, 900 + i * 48, "•  " + n, fontsize=26, color=INK)
    return save(fig, path)


def results_card(path: Path) -> Path:
    fig, ax = canvas()
    ax.text(120, 120, "Proven, attacked and measured", fontsize=52, weight="bold", color=INK)
    rows = [
        (
            "Formal proof (ProVerif)",
            "Secret if X25519 OR ML-KEM is broken; classical mode falls to harvest-now-decrypt-later",
        ),
        (
            "Post-compromise security",
            "After a device theft, a quantum attacker is locked out at the next ML-KEM re-key",
        ),
        (
            "Attack suite",
            "Prekey swap, downgrade and replay blocked; 200,000 fuzz inputs, 0 crashes; ZAP: 0 failures",
        ),
        ("Forensics", "Seized relay and client files: 0 of 20 secrets found in any encoding"),
        ("Cost", "≈ 0.3 ms extra per handshake; the real price is bandwidth (21 KB key bundles)"),
        (
            "Honest limit",
            "First contact needs a safety-number check to rule out a lying relay (same as Signal)",
        ),
    ]
    for i, (head, body) in enumerate(rows):
        y = 260 + i * 125
        color = RED if head == "Honest limit" else BRAND
        ax.add_patch(plt.Rectangle((120, y - 36), 10, 56, color=color))
        ax.text(160, y - 8, head, fontsize=30, weight="bold", color=INK, va="center")
        ax.text(160, y + 36, body, fontsize=25, color=SUB, va="center")
    return save(fig, path)


def end_card(path: Path) -> Path:
    fig, ax = canvas()
    ax.text(W / 2, 430, "Run it yourself", fontsize=64, weight="bold", color=INK, ha="center")
    ax.text(
        W / 2,
        540,
        "git clone https://github.com/Asad3404/PQChat.git",
        fontsize=30,
        color=SUB,
        ha="center",
        family="DejaVu Sans Mono",
    )
    ax.text(
        W / 2,
        600,
        "cd PQChat && scripts/demo.sh",
        fontsize=30,
        color=SUB,
        ha="center",
        family="DejaVu Sans Mono",
    )
    ax.text(
        W / 2,
        760,
        "Then open the two printed links: one for Alice, one for Bob.",
        fontsize=28,
        color=SUB,
        ha="center",
    )
    return save(fig, path)


def live_background(path: Path) -> Path:
    fig, ax = canvas()
    fig.patch.set_facecolor(PANE)
    ax.text(
        40,
        60,
        "Live: two real browsers, one untrusted relay",
        fontsize=34,
        weight="bold",
        color=INK,
        va="center",
    )
    ax.text(
        W / 4,
        115,
        "Alice's browser",
        fontsize=24,
        color=BRAND,
        ha="center",
        va="center",
        weight="bold",
    )
    ax.text(
        3 * W / 4,
        115,
        "Bob's browser",
        fontsize=24,
        color=BRAND,
        ha="center",
        va="center",
        weight="bold",
    )
    ax.add_patch(plt.Rectangle((0, 790), W, 290, color="white"))
    ax.add_patch(plt.Rectangle((0, 790), 14, 290, color=BRAND))
    return save(fig, path)


def card_clip(png: Path, seconds: float, out: Path) -> Path:
    run(
        "-loop",
        "1",
        "-t",
        str(seconds),
        "-i",
        str(png),
        "-vf",
        f"scale={W}:{H},format=yuv420p,fade=t=in:d=0.5,fade=t=out:st={seconds - 0.5}:d=0.5",
        "-r",
        str(FPS),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-preset",
        "medium",
        "-crf",
        "20",
        str(out),
    )
    return out


def live_clip(rec: Path, work: Path, out: Path) -> Path:
    tl = json.loads((rec / "timeline.json").read_text())
    duration, caps = tl["duration"], tl["captions"]
    bg = live_background(work / "live_bg.png")
    filters = [
        "[1:v]scale=960:640,setsar=1[a]",
        "[2:v]scale=960:640,setsar=1[b]",
        "[a][b]hstack=inputs=2[ab]",
        "[0:v][ab]overlay=0:140:shortest=1[v0]",
    ]
    last = "v0"
    for i, c in enumerate(caps):
        start = c["t"]
        end = caps[i + 1]["t"] if i + 1 < len(caps) else duration
        txt = work / f"cap{i}.txt"
        txt.write_text(textwrap.fill(c["text"], width=88))
        step = work / f"step{i}.txt"
        step.write_text(f"Step {i + 1} of {len(caps)}")
        nxt = f"v{i + 1}"
        filters.append(
            f"[{last}]drawtext=fontfile={FONT_BOLD}:textfile={step}:fontsize=26:fontcolor={BRAND}:"
            f"x=60:y=820:enable='between(t,{start:.2f},{end:.2f})',"
            f"drawtext=fontfile={FONT}:textfile={txt}:fontsize=36:fontcolor={INK}:line_spacing=14:"
            f"x=60:y=875:enable='between(t,{start:.2f},{end:.2f})'[{nxt}]"
        )
        last = nxt
    filters.append(
        f"[{last}]format=yuv420p,fade=t=in:d=0.5,fade=t=out:st={duration - 0.6:.2f}:d=0.6[out]"
    )
    run(
        "-loop",
        "1",
        "-t",
        f"{duration:.2f}",
        "-i",
        str(bg),
        "-i",
        str(rec / "alice.webm"),
        "-i",
        str(rec / "bob.webm"),
        "-filter_complex",
        ";".join(filters),
        "-map",
        "[out]",
        "-t",
        f"{duration:.2f}",
        "-r",
        str(FPS),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-preset",
        "medium",
        "-crf",
        "20",
        str(out),
    )
    return out


def main() -> None:
    rec, relay_view, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    if shutil.which("ffmpeg") is None:
        sys.exit("ffmpeg not found")
    work = rec / "build"
    work.mkdir(exist_ok=True)
    clips = [
        card_clip(title_card(work / "c1.png"), 7, work / "s1.mp4"),
        card_clip(architecture_card(work / "c2.png"), 8, work / "s2.mp4"),
        live_clip(rec, work, work / "s3.mp4"),
        card_clip(relay_card(work / "c4.png", relay_view.read_text()), 11, work / "s4.mp4"),
        card_clip(results_card(work / "c5.png"), 11, work / "s5.mp4"),
        card_clip(end_card(work / "c6.png"), 5, work / "s6.mp4"),
    ]
    listing = work / "concat.txt"
    listing.write_text("".join(f"file '{c}'\n" for c in clips))
    out.parent.mkdir(parents=True, exist_ok=True)
    run(
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(listing),
        "-c",
        "copy",
        "-movflags",
        "+faststart",
        str(out),
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
