"""Generate docs/cbom.json: a Cryptographic Bill of Materials in CycloneDX 1.6 (Milestone 10).

    .venv/bin/python scripts/make_cbom.py

Library versions are read from the installed environment, so the CBOM is regenerated whenever the
pins change. Security levels: classicalSecurityLevel in bits; nistQuantumSecurityLevel is the NIST
PQC category (1-5), 0 = broken by a cryptographically relevant quantum computer.
"""

from __future__ import annotations

import datetime
import importlib.metadata as md
import json
import ssl
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def algo(
    ref: str,
    name: str,
    primitive: str,
    functions: list[str],
    *,
    classical: int | None,
    quantum: int | None,
    oid: str | None = None,
    param: str | None = None,
    curve: str | None = None,
    mode: str | None = None,
    where: str = "",
) -> dict:  # type: ignore[type-arg]
    props: dict[str, object] = {
        "primitive": primitive,
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "x86_64",
        "certificationLevel": ["none"],
        "cryptoFunctions": functions,
    }
    if param:
        props["parameterSetIdentifier"] = param
    if curve:
        props["curve"] = curve
    if mode:
        props["mode"] = mode
    if classical is not None:
        props["classicalSecurityLevel"] = classical
    if quantum is not None:
        props["nistQuantumSecurityLevel"] = quantum
    crypto: dict[str, object] = {"assetType": "algorithm", "algorithmProperties": props}
    if oid:
        crypto["oid"] = oid
    comp: dict[str, object] = {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "cryptoProperties": crypto,
    }
    if where:
        comp["description"] = where
    return comp


def material(ref: str, name: str, kind: str, algorithm_ref: str, size: int, where: str) -> dict:  # type: ignore[type-arg]
    return {
        "type": "cryptographic-asset",
        "bom-ref": ref,
        "name": name,
        "description": where,
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": kind,
                "algorithmRef": algorithm_ref,
                "size": size,
            },
        },
    }


def lib(ref: str, name: str, version: str, purl: str, desc: str) -> dict:  # type: ignore[type-arg]
    return {
        "type": "library",
        "bom-ref": ref,
        "name": name,
        "version": version,
        "purl": purl,
        "description": desc,
    }


def main() -> None:
    import oqs

    from pqchat import __version__

    v = md.version
    components = [
        lib(
            "lib-liboqs",
            "liboqs",
            oqs.oqs_version(),
            f"pkg:github/open-quantum-safe/liboqs@{oqs.oqs_version()}",
            "C library: ML-KEM-768 and ML-DSA-65 (minimal build, ADR-001)",
        ),
        lib(
            "lib-liboqs-python",
            "liboqs-python",
            v("liboqs-python"),
            f"pkg:pypi/liboqs-python@{v('liboqs-python')}",
            "Python bindings for liboqs",
        ),
        lib(
            "lib-cryptography",
            "cryptography",
            v("cryptography"),
            f"pkg:pypi/cryptography@{v('cryptography')}",
            "pyca/cryptography: X25519, Ed25519, HKDF, HMAC, SHA-256, AES-GCM, X.509 (backed by OpenSSL)",
        ),
        lib(
            "lib-argon2-cffi",
            "argon2-cffi",
            v("argon2-cffi"),
            f"pkg:pypi/argon2-cffi@{v('argon2-cffi')}",
            "Argon2id for the client key store",
        ),
        lib(
            "lib-openssl",
            "OpenSSL",
            ssl.OPENSSL_VERSION.split()[1],
            f"pkg:generic/openssl@{ssl.OPENSSL_VERSION.split()[1]}",
            "TLS 1.3 for the relay connection (Python ssl module); version is the build environment's",
        ),
        # ---------------------------------------------------------------- algorithms
        algo(
            "alg-mlkem768",
            "ML-KEM-768",
            "kem",
            ["keygen", "encapsulate", "decapsulate"],
            classical=192,
            quantum=3,
            oid="2.16.840.1.101.3.4.4.2",
            param="768",
            where="Hybrid handshake (PQSPK/PQOPK) and ratchet re-keying; FIPS 203",
        ),
        algo(
            "alg-mldsa65",
            "ML-DSA-65",
            "signature",
            ["keygen", "sign", "verify"],
            classical=192,
            quantum=3,
            oid="2.16.840.1.101.3.4.3.18",
            param="65",
            where="Identity signatures on IKdh and every prekey; relay login; FIPS 204",
        ),
        algo(
            "alg-x25519",
            "X25519",
            "key-agree",
            ["keygen", "keyderive"],
            classical=128,
            quantum=0,
            oid="1.3.101.110",
            curve="Curve25519",
            where="Handshake DH1-DH4 and DH ratchet; always combined with ML-KEM in hybrid mode",
        ),
        algo(
            "alg-ed25519",
            "Ed25519",
            "signature",
            ["keygen", "sign", "verify"],
            classical=128,
            quantum=0,
            oid="1.3.101.112",
            curve="Edwards25519",
            where="Identity signatures, always together with ML-DSA-65",
        ),
        algo(
            "alg-aes256gcm",
            "AES-256-GCM",
            "ae",
            ["encrypt", "decrypt"],
            classical=256,
            quantum=5,
            oid="2.16.840.1.101.3.4.1.46",
            param="256",
            mode="gcm",
            where="Message encryption, first message, key store; TLS record layer",
        ),
        algo(
            "alg-hkdf-sha256",
            "HKDF-SHA256",
            "kdf",
            ["keyderive"],
            classical=256,
            quantum=2,
            where="Handshake key schedule, root KDF, message keys (RFC 5869)",
        ),
        algo(
            "alg-hmac-sha256",
            "HMAC-SHA256",
            "mac",
            ["tag", "keyderive"],
            classical=256,
            quantum=2,
            oid="1.2.840.113549.2.9",
            where="Ratchet chain KDF",
        ),
        algo(
            "alg-sha256",
            "SHA-256",
            "hash",
            ["digest"],
            classical=128,
            quantum=2,
            oid="2.16.840.1.101.3.4.2.1",
            where="Prekey binding, replay cache, safety numbers",
        ),
        algo(
            "alg-argon2id",
            "Argon2id",
            "kdf",
            ["keyderive"],
            classical=None,
            quantum=None,
            param="m=65536 KiB, t=3, p=4",
            where="Passphrase -> key-store key (RFC 9106); not NIST-approved",
        ),
        algo(
            "alg-x25519mlkem768",
            "X25519MLKEM768",
            "kem",
            ["keygen", "encapsulate", "decapsulate"],
            classical=128,
            quantum=3,
            where="TLS 1.3 hybrid key-exchange group 0x11EC negotiated by OpenSSL",
        ),
        algo(
            "alg-ecdsa-p256",
            "ECDSA-P256-SHA256",
            "signature",
            ["sign", "verify"],
            classical=128,
            quantum=0,
            oid="1.2.840.10045.4.3.2",
            curve="secp256r1",
            where="Demo TLS certificate of the relay (devcerts.py)",
        ),
        algo(
            "alg-csprng",
            "OS CSPRNG (getrandom)",
            "drbg",
            ["generate"],
            classical=256,
            quantum=None,
            where="os.urandom / secrets and the libraries' RNGs",
        ),
        # ---------------------------------------------------------------- protocols
        {
            "type": "cryptographic-asset",
            "bom-ref": "proto-tls13",
            "name": "TLS 1.3",
            "description": "Client to relay transport; TLS 1.3 only (SR-23)",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "tls",
                    "version": "1.3",
                    "cipherSuites": [
                        {
                            "name": "TLS_AES_256_GCM_SHA384",
                            "identifiers": ["0x13,0x02"],
                            "algorithms": ["alg-aes256gcm", "alg-sha256"],
                        }
                    ],
                    "cryptoRefArray": ["alg-x25519mlkem768", "alg-ecdsa-p256", "alg-aes256gcm"],
                },
            },
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "proto-pqchat-handshake",
            "name": "PQ-Chat v1 hybrid handshake",
            "description": "PQXDH-style handshake, docs/protocol-spec.md section 4",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "other",
                    "version": "1",
                    "cryptoRefArray": [
                        "alg-x25519",
                        "alg-mlkem768",
                        "alg-ed25519",
                        "alg-mldsa65",
                        "alg-hkdf-sha256",
                        "alg-aes256gcm",
                        "alg-sha256",
                    ],
                },
            },
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "proto-pqchat-ratchet",
            "name": "PQ-Chat v1 double ratchet with ML-KEM re-keying",
            "description": "docs/notes/m5-pq-ratchet.md (simplified SPQR)",
            "cryptoProperties": {
                "assetType": "protocol",
                "protocolProperties": {
                    "type": "other",
                    "version": "1",
                    "cryptoRefArray": [
                        "alg-x25519",
                        "alg-mlkem768",
                        "alg-hkdf-sha256",
                        "alg-hmac-sha256",
                        "alg-aes256gcm",
                    ],
                },
            },
        },
        # ---------------------------------------------------------------- key material
        material(
            "key-ik-ed",
            "Identity signing key IKsig-ed",
            "private-key",
            "alg-ed25519",
            256,
            "long-term, client key store",
        ),
        material(
            "key-ik-pq",
            "Identity signing key IKsig-pq",
            "private-key",
            "alg-mldsa65",
            4032 * 8,
            "long-term, client key store",
        ),
        material(
            "key-ik-dh",
            "Identity DH key IKdh",
            "private-key",
            "alg-x25519",
            256,
            "long-term, client key store",
        ),
        material(
            "key-spk",
            "Signed prekeys SPK / PQSPK",
            "private-key",
            "alg-mlkem768",
            2400 * 8,
            "rotated weekly, max 30 days",
        ),
        material(
            "key-opk",
            "One-time prekeys OPK / PQOPK",
            "private-key",
            "alg-mlkem768",
            2400 * 8,
            "deleted after one use",
        ),
        material(
            "key-root",
            "Ratchet root and chain keys",
            "secret-key",
            "alg-hkdf-sha256",
            256,
            "per session, updated every step",
        ),
        material(
            "key-keystore",
            "Key-store encryption key",
            "secret-key",
            "alg-argon2id",
            256,
            "derived from the passphrase, never stored",
        ),
    ]
    provides = {
        "lib-liboqs": ["alg-mlkem768", "alg-mldsa65"],
        "lib-cryptography": [
            "alg-x25519",
            "alg-ed25519",
            "alg-aes256gcm",
            "alg-hkdf-sha256",
            "alg-hmac-sha256",
            "alg-sha256",
            "alg-ecdsa-p256",
        ],
        "lib-argon2-cffi": ["alg-argon2id"],
        "lib-openssl": ["alg-x25519mlkem768", "proto-tls13"],
    }
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, 'pqchat-cbom-' + __version__)}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "component": {
                "type": "application",
                "bom-ref": "pqchat",
                "name": "PQ-Chat",
                "version": __version__,
                "description": "Hybrid post-quantum end-to-end encrypted messenger (MS capstone)",
            },
            "tools": {"components": [{"type": "application", "name": "scripts/make_cbom.py"}]},
        },
        "components": components,
        "dependencies": [
            {
                "ref": "pqchat",
                "dependsOn": [c["bom-ref"] for c in components if c["type"] == "library"],
            },
            *({"ref": k, "provides": v} for k, v in provides.items()),
        ],
    }
    out = ROOT / "docs" / "cbom.json"
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"wrote {out} with {len(components)} components")


if __name__ == "__main__":
    main()
