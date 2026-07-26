"""Atomic request ledger with resumable state."""
from __future__ import annotations

import csv
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class RequestKey:
    """Unique identifier for a request."""
    host: str
    port: int
    method: str
    path: str

    def to_tuple(self) -> tuple[str, int, str, str]:
        return (self.host, self.port, self.method, self.path)


class Ledger:
    """SQLite-backed request ledger."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER,
                    body_hash TEXT,
                    raw_path TEXT,
                    completed INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(host, port, method, path)
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_completed
                ON requests(completed)
                """
            )

            conn.commit()

    def is_completed(self, key: RequestKey) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT 1
                FROM requests
                WHERE host=?
                  AND port=?
                  AND method=?
                  AND path=?
                  AND completed=1
                """,
                key.to_tuple(),
            )
            return cursor.fetchone() is not None

    def record(
        self,
        key: RequestKey,
        status: Optional[int] = None,
        body_hash: Optional[str] = None,
        raw_path: Optional[str] = None,
        completed: bool = True,
    ) -> None:
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO requests (
                        timestamp,
                        host,
                        port,
                        method,
                        path,
                        status,
                        body_hash,
                        raw_path,
                        completed
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

                    ON CONFLICT(host, port, method, path)
                    DO UPDATE SET
                        timestamp=excluded.timestamp,
                        status=excluded.status,
                        body_hash=excluded.body_hash,
                        raw_path=excluded.raw_path,
                        completed=excluded.completed
                    """,
                    (
                        time.time(),
                        key.host,
                        key.port,
                        key.method,
                        key.path,
                        status,
                        body_hash,
                        raw_path,
                        1 if completed else 0,
                    ),
                )
                conn.commit()

    def get_pending(
        self,
        keys: list[RequestKey],
    ) -> list[RequestKey]:
        return [
            key
            for key in keys
            if not self.is_completed(key)
        ]

    def get_completed_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*)
                FROM requests
                WHERE completed=1
                """
            )
            return int(cursor.fetchone()[0])

    def request_count(self) -> int:
        return self.get_completed_count()

    def export_csv(self, path: Path) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT
                    timestamp,
                    host,
                    port,
                    method,
                    path,
                    status,
                    body_hash,
                    raw_path
                FROM requests
                WHERE completed=1
                ORDER BY id
                """
            )

            with path.open(
                "w",
                newline="",
                encoding="utf-8",
            ) as handle:
                writer = csv.writer(handle)

                writer.writerow(
                    [
                        "timestamp",
                        "host",
                        "port",
                        "method",
                        "path",
                        "status",
                        "body_hash",
                        "raw_path",
                    ]
                )

                for row in cursor:
                    writer.writerow(row)

    def to_jsonl(self, path: Path) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT *
                FROM requests
                WHERE completed=1
                ORDER BY id
                """
            )

            columns = [desc[0] for desc in cursor.description]

            with path.open(
                "w",
                encoding="utf-8",
            ) as handle:
                for row in cursor:
                    record = dict(zip(columns, row))
                    handle.write(
                        json.dumps(
                            record,
                            default=str,
                            sort_keys=True,
                        )
                        + "\n"
                    )