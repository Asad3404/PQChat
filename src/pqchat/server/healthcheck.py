"""Container health check: GET /healthz over https (if TLS is configured) or http."""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request


def main() -> int:
    port = os.environ.get("PQCHAT_RELAY_PORT", "8000")
    ctx: ssl.SSLContext | None = None
    url = f"http://127.0.0.1:{port}/healthz"
    cert = os.environ.get("PQCHAT_TLS_CERT")
    if cert:
        # Full verification: chain to the CA next to the certificate, hostname "localhost"
        # (the relay certificate lists it as a subject alternative name).
        ctx = ssl.create_default_context(cafile=os.path.join(os.path.dirname(cert), "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        url = f"https://localhost:{port}/healthz"
    try:
        with urllib.request.urlopen(url, timeout=2, context=ctx) as r:  # noqa: S310  # nosec B310
            return 0 if r.status == 200 else 1
    except OSError:
        return 1


if __name__ == "__main__":
    sys.exit(main())
