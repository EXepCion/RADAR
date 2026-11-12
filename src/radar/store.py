"""Shared SQLite store: alerts plus a namespaced key/value table for plugin state."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    key            TEXT NOT NULL UNIQUE,
    plugin_id      TEXT NOT NULL,
    rule_id        TEXT NOT NULL DEFAULT '',
    severity       INTEGER NOT NULL,
    title          TEXT NOT NULL,
    summary        TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    fields         TEXT NOT NULL DEFAULT '{}',
    evidence       TEXT NOT NULL DEFAULT '[]',
    links          TEXT NOT NULL DEFAULT '[]',
    occurred_at    TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    status         TEXT NOT NULL,
    snooze_until   TEXT,
    dismissed_at   TEXT,
    score          INTEGER NOT NULL DEFAULT 0,
    factors        TEXT NOT NULL DEFAULT '[]',
    seen_at        TEXT,
    subjects       TEXT NOT NULL DEFAULT '[]',
    signal         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status);
CREATE TABLE IF NOT EXISTS kv (
    namespace TEXT NOT NULL,
    key       TEXT NOT NULL,
    value     TEXT NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


class Store:
    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            if str(path) != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            columns = {r[1] for r in self._conn.execute("PRAGMA table_info(alerts)")}
            for name, decl in (("score", "INTEGER NOT NULL DEFAULT 0"), ("factors", "TEXT NOT NULL DEFAULT '[]'"),
                               ("seen_at", "TEXT"), ("subjects", "TEXT NOT NULL DEFAULT '[]'"),
                               ("signal", "TEXT NOT NULL DEFAULT ''")):
                if name not in columns:  # migrate databases created by older versions
                    self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {decl}")
                    if name == "seen_at":  # reminders that existed before this version count as already seen
                        self._conn.execute("UPDATE alerts SET seen_at=first_seen")
            self._conn.commit()

    def execute(self, sql: str, params: tuple | dict = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid if sql.lstrip().upper().startswith("INSERT") else cur.rowcount

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params))

    def query_one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def kv_get(self, namespace: str, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM kv WHERE namespace=? AND key=?", (namespace, key))
        return json.loads(row["value"]) if row else default

    def kv_set(self, namespace: str, key: str, value: Any) -> None:
        self.execute(
            "INSERT INTO kv(namespace, key, value) VALUES(?,?,?) "
            "ON CONFLICT(namespace, key) DO UPDATE SET value=excluded.value",
            (namespace, key, json.dumps(value)),
        )

    def kv_delete(self, namespace: str, key: str | None = None) -> None:
        if key is None:
            self.execute("DELETE FROM kv WHERE namespace=?", (namespace,))
        else:
            self.execute("DELETE FROM kv WHERE namespace=? AND key=?", (namespace, key))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
