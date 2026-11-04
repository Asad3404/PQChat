"""Relay server (stub for Milestone 0).

The real relay (prekey bundles, message queues, WebSocket API) arrives in Milestone 6.
For now it exposes one health endpoint so Docker Compose and CI can prove the
container starts.

Hardening already applied:
* The auto-generated OpenAPI/Swagger pages are disabled: an untrusted, internet-facing
  relay should not advertise its own API surface.
* Default bind address is localhost; Docker sets PQCHAT_RELAY_HOST=0.0.0.0 explicitly.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from pqchat import PROTOCOL_VERSION, __version__

app = FastAPI(
    title="PQ-Chat relay",
    version=__version__,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/healthz")
def healthz() -> dict[str, object]:
    """Liveness probe. Returns no user data."""
    return {"status": "ok", "service": "pqchat-relay", "protocol_version": PROTOCOL_VERSION}


def main() -> None:
    import uvicorn

    host = os.environ.get("PQCHAT_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("PQCHAT_RELAY_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, server_header=False, log_level="info")


if __name__ == "__main__":
    main()
