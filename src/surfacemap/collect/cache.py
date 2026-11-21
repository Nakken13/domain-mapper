"""SQLite response cache with a time-to-live, keyed by `(source, query)`.

The key is the *logical* query a plugin sent (e.g. `%.example.com` for crt.sh), the
same string recorded in `Provenance.query`, never a URL: an API key passed as a URL
parameter can therefore never be written to disk. Source and query are two separate
key columns, so no concatenation can make two different keys collide.

Callers store only successful responses (no 429/5xx), so an outage is never cached.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Self

Clock = Callable[[], datetime]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS responses (
    source    TEXT NOT NULL,
    query     TEXT NOT NULL,
    body      TEXT NOT NULL,
    stored_at REAL NOT NULL,
    PRIMARY KEY (source, query)
)
"""


def utc_now() -> datetime:
    return datetime.now(UTC)


class ResponseCache:
    def __init__(self, path: Path, ttl: timedelta, clock: Clock = utc_now) -> None:
        if ttl <= timedelta(0):
            raise ValueError("cache ttl must be positive")
        self._ttl = ttl.total_seconds()
        self._clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        with self._db:
            self._db.execute(_SCHEMA)

    def _now(self) -> float:
        return self._clock().timestamp()

    def get(self, source: str, query: str) -> str | None:
        """The stored body, or None when absent or older than the TTL."""
        row = self._db.execute(
            "SELECT body FROM responses WHERE source = ? AND query = ? AND stored_at > ?",
            (source, query, self._now() - self._ttl),
        ).fetchone()
        return None if row is None else str(row[0])

    def set(self, source: str, query: str, body: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?)",
                (source, query, body, self._now()),
            )

    def purge_expired(self) -> int:
        """Delete stale rows; return how many were removed."""
        with self._db:
            cursor = self._db.execute(
                "DELETE FROM responses WHERE stored_at <= ?", (self._now() - self._ttl,)
            )
        return cursor.rowcount

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
