"""NIST ACVP known-answer tests for ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204).

Data: tests/vectors/data/acvp_pq.json, extracted from NIST's ACVP-Server repository by
tests/vectors/extract_acvp.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import oqs
import pytest

from pqchat.crypto import kem
from pqchat.crypto.errors import CryptoError

DATA: dict[str, Any] = json.loads(
    (Path(__file__).parent / "data" / "acvp_pq.json").read_text(encoding="utf-8")
)
h = bytes.fromhex


def _ids(cases: list[dict[str, Any]]) -> list[str]:
    return [f"tc{c['tcId']}" for c in cases]


KEYGEN = DATA["mlkem768_keygen"]
DECAPS = [c for c in DATA["mlkem768_encdec"] if c["function"] in ("encapsulation", "decapsulation")]
EKCHECK = [c for c in DATA["mlkem768_encdec"] if c["function"] == "encapsulationKeyCheck"]
SIGVER = DATA["mldsa65_sigver_pure"]


def test_vector_counts() -> None:
    assert (len(KEYGEN), len(DECAPS), len(EKCHECK), len(SIGVER)) == (25, 35, 10, 15)


@pytest.mark.parametrize("case", KEYGEN, ids=_ids(KEYGEN))
def test_mlkem768_keygen(case: dict[str, Any]) -> None:
    kp = kem.MLKEMKeyPair.from_seed(h(case["d"] + case["z"]))
    assert kp.public == h(case["ek"])
    assert kp.secret_bytes() == h(case["dk"])


@pytest.mark.parametrize("case", DECAPS, ids=_ids(DECAPS))
def test_mlkem768_decapsulation(case: dict[str, Any]) -> None:
    """Includes invalid ciphertexts: the expected K is the implicit-rejection value."""
    kp = kem.MLKEMKeyPair(h(case["ek"]), h(case["dk"]))
    assert kp.decapsulate(h(case["c"])) == h(case["k"])


@pytest.mark.parametrize("case", EKCHECK, ids=_ids(EKCHECK))
def test_mlkem768_encapsulation_key_check(case: dict[str, Any]) -> None:
    """FIPS 203 §7.2 modulus check: malformed public keys must be rejected."""
    if case["testPassed"]:
        ct, ss = kem.encapsulate(h(case["ek"]))
        assert len(ct) == kem.CIPHERTEXT_LEN and len(ss) == kem.SHARED_SECRET_LEN
    else:
        with pytest.raises(CryptoError):
            kem.encapsulate(h(case["ek"]))


@pytest.mark.parametrize("case", SIGVER, ids=_ids(SIGVER))
def test_mldsa65_sigver(case: dict[str, Any]) -> None:
    with oqs.Signature("ML-DSA-65") as v:
        ok = v.verify_with_ctx_str(
            h(case["message"]), h(case["signature"]), h(case["context"]), h(case["pk"])
        )
    assert ok == case["testPassed"]
