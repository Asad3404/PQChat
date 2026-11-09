"""Create a throw-away CA and a relay certificate for the Docker demo (M7).

Usage: python -m pqchat.server.devcerts OUT_DIR HOSTNAME

Demo only: in a real deployment the relay certificate comes from a public CA (e.g. ACME).
The CA private key is deleted after signing, so the demo CA cannot issue further certificates.
Note: X.509 here is classical (ECDSA P-256); message security never depends on TLS.
"""

from __future__ import annotations

import datetime
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make(out: Path, hostname: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    if (out / "relay.crt").exists():
        return
    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("PQ-Chat demo CA"))
        .issuer_name(_name("PQ-Chat demo CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(hostname))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName("localhost")]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (out / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (out / "relay.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(out / "relay.key", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    del ca_key  # never written to disk


if __name__ == "__main__":
    make(Path(sys.argv[1]), sys.argv[2])
