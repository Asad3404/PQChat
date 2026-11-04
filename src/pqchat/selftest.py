"""Start-up self-test: proves the liboqs C library is installed and working.

This is the "known-good" check that runs in CI, in the Docker images and at client
start-up. It deliberately prints *only* pass/fail and public sizes, never key
material or shared secrets (CLAUDE.md §3.4).

Note: Milestone 2 introduces the real wrappers in ``pqchat.crypto``; this module
will then call those wrappers instead of ``oqs`` directly.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

import oqs

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"
EXPECTED_LIBOQS_VERSION = "0.16.0"


@dataclass(frozen=True)
class SelfTestResult:
    liboqs_version: str
    kem_ok: bool
    sig_ok: bool

    @property
    def ok(self) -> bool:
        return self.kem_ok and self.sig_ok and self.liboqs_version == EXPECTED_LIBOQS_VERSION


def _kem_roundtrip() -> bool:
    with oqs.KeyEncapsulation(KEM_ALG) as receiver:
        public_key = receiver.generate_keypair()
        with oqs.KeyEncapsulation(KEM_ALG) as sender:
            ciphertext, ss_sender = sender.encap_secret(public_key)
        ss_receiver = receiver.decap_secret(ciphertext)
    # Constant-time comparison even in a self-test: good habit (CLAUDE.md §3.3).
    return bool(hmac.compare_digest(ss_sender, ss_receiver))


def _sig_roundtrip() -> bool:
    message = b"PQChat-v1 self-test"
    with oqs.Signature(SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
    with oqs.Signature(SIG_ALG) as verifier:
        good = bool(verifier.verify(message, signature, public_key))
        bad = bool(verifier.verify(message + b"!", signature, public_key))
    return good and not bad


def run() -> SelfTestResult:
    return SelfTestResult(
        liboqs_version=oqs.oqs_version(),
        kem_ok=_kem_roundtrip(),
        sig_ok=_sig_roundtrip(),
    )


def main() -> int:
    result = run()
    print(  # noqa: T201 - CLI output, contains no secrets
        f"liboqs {result.liboqs_version}: "
        f"{KEM_ALG} {'OK' if result.kem_ok else 'FAIL'}, "
        f"{SIG_ALG} {'OK' if result.sig_ok else 'FAIL'}"
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
