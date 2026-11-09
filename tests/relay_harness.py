"""Start a real relay (uvicorn) on a free localhost port for tests."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn

from pqchat.server.app import create_app
from pqchat.server.ratelimit import RateLimiter
from pqchat.server.storage import Storage


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def running_relay(
    storage: Storage | None = None, limiter: RateLimiter | None = None, **config: object
) -> Iterator[tuple[str, Storage]]:
    storage = storage or Storage(":memory:")
    port = free_port()
    app = create_app(storage, limiter)
    cfg = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", server_header=False, **config
    )  # type: ignore[arg-type]
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("relay did not start")
        time.sleep(0.02)
    try:
        yield f"127.0.0.1:{port}", storage
    finally:
        server.should_exit = True
        thread.join(timeout=5)
