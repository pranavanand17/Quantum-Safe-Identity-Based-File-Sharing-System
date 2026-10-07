"""Security event logging. Never log keys or plaintext file contents."""

from __future__ import annotations

from datetime import datetime, timezone

from database import get_db


def log_event(user_id: str | None, event: str, file_id: str | None = None, details: str | None = None) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO activity_logs (user_id, event, file_id, details, timestamp)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, event, file_id, details, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()


def list_events(limit: int = 200) -> list:
    return get_db().execute(
        """
        SELECT id, user_id, event, file_id, details, timestamp
        FROM activity_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
