"""SQLite helpers and idempotent demo-user seeding."""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app, g

from config import DEMO_USERS
from crypto.key_manager import ensure_user_keys

logger = logging.getLogger(__name__)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        path = current_app.config["DATABASE"]
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_error=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            student_id TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            private_key_reference TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_filename TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            recipient_id TEXT NOT NULL,
            encrypted_path TEXT NOT NULL,
            metadata_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(student_id),
            FOREIGN KEY (recipient_id) REFERENCES users(student_id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            event TEXT NOT NULL,
            file_id TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        );
        """
    )
    conn.commit()


def seed_demo_users(conn: sqlite3.Connection, keys_dir: Path) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for demo in DEMO_USERS:
        existing = conn.execute(
            "SELECT id, public_key, private_key_reference FROM users WHERE student_id = ?",
            (demo["student_id"],),
        ).fetchone()
        if existing:
            continue
        public_b64, key_ref = ensure_user_keys(demo["student_id"], keys_dir)
        conn.execute(
            """
            INSERT INTO users (name, student_id, email, public_key, private_key_reference, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                demo["name"],
                demo["student_id"],
                demo["email"],
                public_b64,
                key_ref,
                now,
            ),
        )
        logger.info("Seeded demo user %s", demo["student_id"])
    conn.commit()


def init_db(app) -> None:
    with app.app_context():
        conn = get_db()
        init_schema(conn)
        seed_demo_users(conn, Path(app.config["KEYS_DIR"]))
