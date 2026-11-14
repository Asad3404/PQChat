"""Forensic acquisition and search of PQ-Chat data at rest (Milestone 9, SR-19, SR-26, SR-27).

Two ways to use it:

  python forensics/image_and_search.py --demo
      Runs a synthetic scenario (in-process relay with a file database, two clients, a chat in
      which some messages are delivered and therefore deleted), then images and searches it with
      full ground truth: every passphrase, plaintext and private key used is known and searched for.

  python forensics/image_and_search.py --relay-db relay.db --client-dir alice/ --marker "some text"
      Images and searches existing artefacts (e.g. copied out of the Docker volumes with
      `docker compose cp relay:/data/relay.db .`) for the given plaintext markers.

Steps (classic acquisition -> verification -> analysis):
1. Hash every source file (SHA-256), copy it into the case folder, hash the copy again: the
   copy is only analysed if both hashes match (integrity / chain of custody).
2. Byte-level search of every imaged file (including SQLite -wal/-shm and free pages) for each
   secret in four encodings: raw, hex, base64, base64url.
3. Structured analysis of the relay database: tables, row counts, which columns hold what.

Output: <case>/report.json and a summary on stdout. Synthetic data only (CLAUDE.md §10).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def acquire(sources: list[Path], case: Path) -> list[dict[str, object]]:
    """Copy each source file (or every file in a source directory) into the case folder."""
    log = []
    files: list[tuple[Path, Path]] = []
    for src in sources:
        if src.is_dir():
            files += [
                (p, Path(src.name) / p.relative_to(src))
                for p in sorted(src.rglob("*"))
                if p.is_file()
            ]
        elif src.exists():
            files.append((src, Path(src.name)))
        # SQLite keeps recent changes in side files: image them too.
        for side in ("-wal", "-shm", "-journal"):
            extra = Path(str(src) + side)
            if extra.exists():
                files.append((extra, Path(extra.name)))
    for src, rel in files:
        before = sha256(src)
        dst = case / "image" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        after = sha256(dst)
        log.append(
            {
                "source": str(src),
                "image": str(dst.relative_to(case)),
                "bytes": dst.stat().st_size,
                "sha256_source": before,
                "sha256_image": after,
                "verified": before == after,
                "acquired_utc": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            }
        )
    return log


def encodings(secret: bytes) -> dict[str, bytes]:
    return {
        "raw": secret,
        "hex": secret.hex().encode(),
        "base64": base64.b64encode(secret).rstrip(b"="),
        "base64url": base64.urlsafe_b64encode(secret).rstrip(b"="),
    }


CHUNK = 33  # multiple of 3, so base64(chunk) is an exact substring of base64(secret)


def fragments(secret: bytes) -> list[bytes]:
    """Long values are split across SQLite overflow pages (4-byte page pointers interleave the
    data), so a long secret is searched as aligned 33-byte fragments: any fragment found is a
    leak. Found by the positive control: a whole-value search missed a 1,952-byte public key."""
    if len(secret) <= CHUNK:
        return [secret]
    return [secret[i : i + CHUNK] for i in range(0, len(secret) - CHUNK + 1, CHUNK)]


def mlkem_secret_parts(dk: bytes) -> dict[str, bytes]:
    """FIPS 203: dk = dk_PKE (1152) || ek (1184) || H(ek) (32) || z (32) for ML-KEM-768.
    ek and H(ek) are public, so only dk_PKE and z are searched (otherwise every relay that
    stores the public key would look like a leak: the first version of this script reported
    exactly that false positive)."""
    return {"mlkem_dk_pke": dk[:1152], "mlkem_z": dk[-32:]}


def mldsa_secret_parts(sk: bytes) -> dict[str, bytes]:
    """FIPS 204: sk = rho (32) || K (32) || tr (64) || s1 || s2 || t0. rho is part of the public
    key and tr = H(pk) is public too; K and s1 || s2 || t0 are secret."""
    return {"mldsa_K": sk[32:64], "mldsa_s1_s2_t0": sk[128:]}


def search(case: Path, secrets: dict[str, bytes]) -> list[dict[str, object]]:
    hits = []
    images = {p: p.read_bytes() for p in (case / "image").rglob("*") if p.is_file()}
    for name, secret in secrets.items():
        found = False
        for frag_no, frag in enumerate(fragments(secret)):
            for enc, needle in encodings(frag).items():
                if len(needle) < 8:  # too short to be meaningful evidence
                    continue
                for img, data in images.items():
                    off = data.find(needle)
                    if off >= 0:
                        hits.append(
                            {
                                "secret": name,
                                "fragment": frag_no,
                                "encoding": enc,
                                "file": str(img.relative_to(case)),
                                "offset": off,
                            }
                        )
                        found = True
                        break
                if found:
                    break
            if found:
                break
    return hits


def analyse_relay_db(db: Path) -> dict[str, object]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)  # read-only: never modify evidence
    try:
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        out: dict[str, object] = {"tables": {}}
        for t in tables:
            if not t.isidentifier():
                continue
            cols = [r[1] for r in con.execute(f"PRAGMA table_info({t})")]
            (count,) = con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()  # noqa: S608
            out["tables"][t] = {"columns": cols, "rows": count}  # type: ignore[index]
        out["usernames"] = (
            [r[0] for r in con.execute("SELECT username FROM accounts")]
            if "accounts" in tables
            else []
        )
        if "queue" in tables:
            out["queued_messages"] = [
                {"recipient": r[0], "sender": r[1], "kind": r[2], "blob_bytes": r[3]}
                for r in con.execute("SELECT recipient, sender, kind, length(blob) FROM queue")
            ]
        (fl,) = con.execute("PRAGMA freelist_count").fetchone()
        out["free_pages"] = fl
        return out
    finally:
        con.close()


async def demo_scenario(work: Path) -> tuple[list[Path], dict[str, bytes], Path]:
    from tests.relay_harness import running_relay

    from pqchat.client.core import ChatClient
    from pqchat.server.storage import Storage

    passphrase = "forensics synthetic passphrase"  # noqa: S105 - synthetic test account
    db = work / "relay" / "relay.db"
    db.parent.mkdir(parents=True)
    texts = {
        "delivered_msg_1": "FORENSIC-MARKER delivered message one",
        "delivered_msg_2": "FORENSIC-MARKER delivered reply two",
        "pending_msg": "FORENSIC-MARKER message still waiting on the relay",
    }
    storage = Storage(db)
    stored: list[bytes] = []
    original_enqueue = storage.enqueue

    def record(recipient: str, sender: str, kind: str, blob: bytes, now: int) -> int:
        stored.append(blob)  # ground truth: every ciphertext the relay ever stored
        return original_enqueue(recipient, sender, kind, blob, now)

    storage.enqueue = record  # type: ignore[method-assign]
    with running_relay(storage) as (addr, _):
        url = f"ws://{addr}/ws"
        alice, bob = ChatClient(work / "alice", url), ChatClient(work / "bob", url)
        alice.unlock("alice", passphrase)
        bob.unlock("bob", passphrase)
        await alice.connect()
        await bob.connect()
        await alice.send_text("bob", texts["delivered_msg_1"])
        for _ in range(100):
            if bob.state and bob.state.history.get("alice"):
                break
            await asyncio.sleep(0.05)
        await bob.send_text("alice", texts["delivered_msg_2"])
        await asyncio.sleep(0.5)
        await bob.close()  # bob goes offline, so the next message stays queued on the relay
        await alice.send_text("bob", texts["pending_msg"])
        await asyncio.sleep(0.3)
        secrets: dict[str, bytes] = {"passphrase": passphrase.encode()}
        secrets |= {k: v.encode() for k, v in texts.items()}
        for who, c in (("alice", alice), ("bob", bob)):
            st = c.state
            assert st is not None
            ed, pq = st.identity.signing.private_parts()
            secrets[f"{who}_identity_ed25519_private"] = bytes(ed)
            secrets |= {f"{who}_identity_{k}": v for k, v in mldsa_secret_parts(bytes(pq)).items()}
            secrets[f"{who}_identity_x25519_private"] = bytes(st.identity.dh.private_bytes())
            kp, _ = next(iter(st.prekeys.signed_kem.values()))
            secrets |= {
                f"{who}_signed_{k}": v
                for k, v in mlkem_secret_parts(bytes(kp.secret_bytes())).items()
            }
            for peer, s in st.sessions.items():
                secrets[f"{who}_session_{peer}_root_key"] = bytes(s.ratchet.state.rk)
        await alice.close()
    # The first two ciphertexts were delivered and acknowledged: SR-20 says they must be gone
    # from the relay's files (deleted rows are overwritten thanks to PRAGMA secure_delete).
    for i, blob in enumerate(stored[:-1]):
        secrets[f"deleted_ciphertext_{i}"] = blob[
            -64:
        ]  # tail of the AEAD output: unique per message
    storage.close()
    # Positive controls: data that MUST be found, proving the search works at all.
    controls = {
        "control_pending_ciphertext": stored[-1][-64:],  # still queued for offline bob
        "control_alice_mldsa_public_key": alice.state.identity.public.sign.mldsa65,  # type: ignore[union-attr]
    }
    secrets |= controls
    return [db, work / "alice", work / "bob"], secrets, db


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--relay-db", type=Path)
    ap.add_argument("--client-dir", type=Path, action="append", default=[])
    ap.add_argument("--marker", action="append", default=[])
    ap.add_argument("--case", type=Path, default=ROOT / "evidence" / "m9" / "case")
    args = ap.parse_args()

    if args.case.exists():
        shutil.rmtree(args.case)
    args.case.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        if args.demo:
            sources, secrets, db = asyncio.run(demo_scenario(Path(tmp)))
        else:
            sources = ([args.relay_db] if args.relay_db else []) + args.client_dir
            secrets = {f"marker_{i}": m.encode() for i, m in enumerate(args.marker)}
            db = args.relay_db
        custody = acquire(sources, args.case)
    all_hits = search(args.case, secrets)
    hits = [h for h in all_hits if not str(h["secret"]).startswith("control_")]
    controls = sorted(
        {str(h["secret"]) for h in all_hits if str(h["secret"]).startswith("control_")}
    )
    expected_controls = sorted(k for k in secrets if k.startswith("control_"))
    relay_db_image = next(
        (args.case / c["image"] for c in custody if str(c["image"]).endswith(".db")), None
    )
    db_analysis = analyse_relay_db(relay_db_image) if relay_db_image else {}
    report = {
        "custody": custody,
        "all_images_verified": all(c["verified"] for c in custody),
        "secrets_searched": sorted(secrets),
        "encodings": ["raw", "hex", "base64", "base64url"],
        "hits": hits,
        "positive_controls_expected": expected_controls,
        "positive_controls_found": controls,
        "relay_db": db_analysis,
    }
    (args.case / "report.json").write_text(json.dumps(report, indent=2))
    print(f"imaged files: {len(custody)} (hashes verified: {report['all_images_verified']})")
    print(
        f"secrets searched: {len(secrets) - len(expected_controls)} x 4 encodings, in 33-byte fragments; hits: {len(hits)}"
    )
    print(f"positive controls found: {controls} (expected {expected_controls})")
    for h in hits:
        print(f"  HIT {h['secret']} ({h['encoding']}) in {h['file']} @ {h['offset']}")
    if db_analysis:
        print(f"relay tables: { {t: v['rows'] for t, v in db_analysis['tables'].items()} }")
        print(
            f"relay metadata: usernames={db_analysis['usernames']} queued={db_analysis.get('queued_messages')}"
        )
    _ = db
    sys.exit(1 if hits or controls != expected_controls else 0)


if __name__ == "__main__":
    main()
