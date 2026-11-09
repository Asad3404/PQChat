"""Extract the ML-KEM-768 / ML-DSA-65 subsets of NIST's ACVP vectors into tests/vectors/data/.

Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  ML-KEM-keyGen-FIPS203/internalProjection.json
  ML-KEM-encapDecap-FIPS203/internalProjection.json
  ML-DSA-sigVer-FIPS204/internalProjection.json

Usage: python tests/vectors/extract_acvp.py KEYGEN.json ENCDEC.json SIGVER.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).parent / "data"


def _groups(path: str) -> list[dict[str, object]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return list(data["testGroups"])


def main(keygen: str, encdec: str, sigver: str) -> None:
    OUT.mkdir(exist_ok=True)
    kg = [g for g in _groups(keygen) if g["parameterSet"] == "ML-KEM-768"]
    ed = [g for g in _groups(encdec) if g["parameterSet"] == "ML-KEM-768"]
    sv = [
        g
        for g in _groups(sigver)
        if g["parameterSet"] == "ML-DSA-65"
        and g["signatureInterface"] == "external"
        and g["preHash"] == "pure"
    ]
    out = {
        "source": "NIST ACVP-Server gen-val/json-files (FIPS 203 / FIPS 204 internalProjection)",
        "mlkem768_keygen": [t for g in kg for t in g["tests"]],  # type: ignore[union-attr]
        "mlkem768_encdec": [
            {"function": g["function"], **t}
            for g in ed
            if g["function"] != "decapsulationKeyCheck"  # we never import foreign keys
            for t in g["tests"]  # type: ignore[union-attr]
        ],
        "mldsa65_sigver_pure": [t for g in sv for t in g["tests"]],  # type: ignore[union-attr]
    }
    (OUT / "acvp_pq.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main(*sys.argv[1:4])
