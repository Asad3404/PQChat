"""Container health check: GET /healthz over HTTPS (if TLS is configured) or HTTP.

Uses http.client with a fixed host, so no URL parsing is involved (urllib would also accept
file:// URLs; Semgrep rule dynamic-urllib-use-detected, CI run #4).
"""

from __future__ import annotations

import http.client
import os
import ssl
import sys


def main() -> int:
    port = int(os.environ.get("PQCHAT_RELAY_PORT", "8000"))
    cert = os.environ.get("PQCHAT_TLS_CERT")
    conn: http.client.HTTPConnection
    if cert:
        # Full verification: chain to the CA next to the certificate, hostname "localhost"
        # (the relay certificate lists it as a subject alternative name).
        ctx = ssl.create_default_context(cafile=os.path.join(os.path.dirname(cert), "ca.crt"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        # Python 3.12 with an explicit context that verifies chain and hostname (tested in
        # tests/unit/test_healthcheck.py); the rule targets Pythons < 3.4.3.
        # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        conn = http.client.HTTPSConnection("localhost", port, timeout=2, context=ctx)
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", "/healthz")
        return 0 if conn.getresponse().status == 200 else 1
    except OSError:
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
