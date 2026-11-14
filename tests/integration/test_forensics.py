"""M9: the forensic search finds what it should and nothing that is not a leak."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from forensics.image_and_search import fragments, mlkem_secret_parts, search

from pqchat.crypto.kem import MLKEMKeyPair

ROOT = Path(__file__).resolve().parents[2]


def _case(tmp: Path, content: bytes) -> Path:
    (tmp / "image").mkdir()
    (tmp / "image" / "disk.bin").write_bytes(content)
    return tmp


def test_secret_split_by_page_pointers_is_still_found(tmp_path: Path) -> None:
    secret = os.urandom(200)
    # Simulate an SQLite overflow page: a 4-byte pointer inserted inside the value.
    disk = os.urandom(50) + secret[:120] + b"\x00\x00\x01\x02" + secret[120:] + os.urandom(50)
    assert secret not in disk  # a whole-value search would miss it
    hits = search(_case(tmp_path, disk), {"planted": secret})
    assert hits and hits[0]["secret"] == "planted"  # noqa: S105 - test label, not a password


def test_encoded_secret_is_found(tmp_path: Path) -> None:
    import base64

    secret = os.urandom(99)
    disk = b"junk " + base64.urlsafe_b64encode(secret).rstrip(b"=") + b" junk"
    assert search(_case(tmp_path, disk), {"s": secret})[0]["encoding"] == "base64url"


def test_public_key_inside_mlkem_secret_is_not_a_leak(tmp_path: Path) -> None:
    kp = MLKEMKeyPair.generate()
    disk = b"relay row: " + kp.public  # the relay legitimately stores the public key
    whole = search(_case(tmp_path, disk), {"dk": bytes(kp.secret_bytes())})
    assert whole, "naive search would wrongly flag the embedded public key"
    parts = mlkem_secret_parts(bytes(kp.secret_bytes()))
    assert search(tmp_path, parts) == []


def test_fragments_cover_the_whole_secret() -> None:
    s = bytes(range(100))
    assert b"".join(fragments(s)) == s[: 33 * 3]
    assert fragments(b"short") == [b"short"]


def test_demo_scenario_has_no_leaks(tmp_path: Path) -> None:
    out = subprocess.run(  # noqa: S603 - fixed local command
        [
            sys.executable,
            str(ROOT / "forensics" / "image_and_search.py"),
            "--demo",
            "--case",
            str(tmp_path / "case"),
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "hits: 0" in out.stdout
