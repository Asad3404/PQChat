"""Relay storage (SQLite). Holds only public keys, signatures and ciphertext (SR-19).

* Every query is parameterised (SR-30); no string formatting of SQL.
* Messages are deleted when the recipient acknowledges them, and in any case after the retention
  period (SR-20). Each one-time prekey is handed out once and deleted at that moment (SR-10).
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

RETENTION_SECONDS = 30 * 86_400
MAX_ONE_TIME_PER_KIND = 200

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    username   TEXT PRIMARY KEY,
    identity   BLOB NOT NULL,          -- IdentityPublic encoding (public keys + signatures)
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_prekeys (
    username   TEXT NOT NULL REFERENCES accounts(username),
    alg        INTEGER NOT NULL,       -- 1 = X25519, 3 = ML-KEM-768
    key_id     INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    blob       BLOB NOT NULL,          -- signed prekey encoding (public)
    PRIMARY KEY (username, alg, key_id)
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    username   TEXT NOT NULL REFERENCES accounts(username),
    alg        INTEGER NOT NULL,
    key_id     INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    blob       BLOB NOT NULL,
    PRIMARY KEY (username, alg, key_id)
);
CREATE TABLE IF NOT EXISTS queue (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient  TEXT NOT NULL,
    sender     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    blob       BLOB NOT NULL,          -- end-to-end ciphertext, opaque to the relay
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS queue_recipient ON queue(recipient);
"""


@dataclass(frozen=True)
class QueuedMessage:
    id: int
    sender: str
    kind: str
    blob: bytes


class Storage:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        if str(path) != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA secure_delete=ON")  # overwrite deleted rows on disk (M9)
        self._db.executescript(SCHEMA)

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ accounts
    def get_identity(self, username: str) -> bytes | None:
        with self._lock:
            row = self._db.execute(
                "SELECT identity FROM accounts WHERE username = ?", (username,)
            ).fetchone()
        return bytes(row[0]) if row else None

    def create_account(self, username: str, identity: bytes, now: int) -> bool:
        """False if the name is taken: a name stays bound to its first identity (SR-21)."""
        with self._tx() as db:
            if db.execute("SELECT 1 FROM accounts WHERE username = ?", (username,)).fetchone():
                return False
            db.execute(
                "INSERT INTO accounts (username, identity, created_at) VALUES (?, ?, ?)",
                (username, identity, now),
            )
        return True

    # ------------------------------------------------------------------ prekeys
    def put_signed_prekey(
        self, username: str, alg: int, key_id: int, created: int, expires: int, blob: bytes
    ) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT OR REPLACE INTO signed_prekeys VALUES (?, ?, ?, ?, ?, ?)",
                (username, alg, key_id, created, expires, blob),
            )

    def newest_signed_prekey(self, username: str, alg: int, now: int) -> bytes | None:
        with self._lock:
            row = self._db.execute(
                "SELECT blob FROM signed_prekeys WHERE username = ? AND alg = ? AND expires_at > ?"
                " ORDER BY created_at DESC LIMIT 1",
                (username, alg, now),
            ).fetchone()
        return bytes(row[0]) if row else None

    def add_one_time(self, username: str, alg: int, key_id: int, expires: int, blob: bytes) -> bool:
        with self._tx() as db:
            (count,) = db.execute(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE username = ? AND alg = ?",
                (username, alg),
            ).fetchone()
            if count >= MAX_ONE_TIME_PER_KIND:
                return False
            db.execute(
                "INSERT OR IGNORE INTO one_time_prekeys VALUES (?, ?, ?, ?, ?)",
                (username, alg, key_id, expires, blob),
            )
        return True

    def take_one_time(self, username: str, alg: int, now: int) -> bytes | None:
        """Hand out one unexpired one-time prekey and delete it in the same transaction."""
        with self._tx() as db:
            row = db.execute(
                "SELECT key_id, blob FROM one_time_prekeys WHERE username = ? AND alg = ?"
                " AND expires_at > ? LIMIT 1",
                (username, alg, now),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "DELETE FROM one_time_prekeys WHERE username = ? AND alg = ? AND key_id = ?",
                (username, alg, row[0]),
            )
        return bytes(row[1])

    def count_one_time(self, username: str, alg: int) -> int:
        with self._lock:
            (count,) = self._db.execute(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE username = ? AND alg = ?",
                (username, alg),
            ).fetchone()
        return int(count)

    # ------------------------------------------------------------------ queue
    def enqueue(self, recipient: str, sender: str, kind: str, blob: bytes, now: int) -> int:
        with self._tx() as db:
            cur = db.execute(
                "INSERT INTO queue (recipient, sender, kind, blob, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (recipient, sender, kind, blob, now, now + RETENTION_SECONDS),
            )
            return int(cur.lastrowid or 0)

    def pending(self, recipient: str, now: int) -> list[QueuedMessage]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, sender, kind, blob FROM queue WHERE recipient = ? AND expires_at > ?"
                " ORDER BY id",
                (recipient, now),
            ).fetchall()
        return [QueuedMessage(int(r[0]), r[1], r[2], bytes(r[3])) for r in rows]

    def ack(self, recipient: str, message_id: int) -> None:
        """Delete a delivered message. Only its recipient can acknowledge it."""
        with self._tx() as db:
            db.execute("DELETE FROM queue WHERE id = ? AND recipient = ?", (message_id, recipient))

    def purge_expired(self, now: int) -> int:
        with self._tx() as db:
            n = db.execute("DELETE FROM queue WHERE expires_at <= ?", (now,)).rowcount
            n += db.execute("DELETE FROM one_time_prekeys WHERE expires_at <= ?", (now,)).rowcount
            n += db.execute("DELETE FROM signed_prekeys WHERE expires_at <= ?", (now,)).rowcount
        return int(n)

    def close(self) -> None:
        with self._lock:
            self._db.close()
