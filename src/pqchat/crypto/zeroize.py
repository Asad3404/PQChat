"""Best-effort erasure of secrets held in mutable buffers (SR-15, CLAUDE.md §3.11).

Python limits: ``bytes`` are immutable and may be copied by the interpreter, the
allocator or the C libraries, so only our own ``bytearray`` buffers can be overwritten.
This reduces how long secrets stay in memory; it cannot guarantee they are gone.
"""

from __future__ import annotations


def wipe(*buffers: bytearray | None) -> None:
    """Overwrite each buffer with zeros in place."""
    for buf in buffers:
        if buf is not None:
            buf[:] = bytes(len(buf))
