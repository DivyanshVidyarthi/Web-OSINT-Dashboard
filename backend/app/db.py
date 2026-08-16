"""
Lightweight SQLite persistence for investigation history.
No sensitive credentials or raw API keys are ever stored here —
only the investigation results that were already shown to the user.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);
"""


def _db_path() -> str:
    path = get_settings().DATABASE_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return path


@contextmanager
def get_conn():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.execute(_SCHEMA)


def save_investigation(investigation_id: str, target: str, target_type: str,
                        status: str, result: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO investigations (id, target, target_type, status, created_at, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                investigation_id, target, target_type, status,
                datetime.now(timezone.utc).isoformat(), json.dumps(result),
            ),
        )


def list_investigations(limit: int = 100) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, target, target_type, status, created_at FROM investigations "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_investigation(investigation_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
    if not row:
        return None
    data = dict(row)
    data["result"] = json.loads(data.pop("result_json"))
    return data


def delete_investigation(investigation_id: str) -> bool:
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
    return cur.rowcount > 0


def clear_history() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM investigations")
