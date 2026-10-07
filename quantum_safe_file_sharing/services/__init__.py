"""Identity lookup: student_id → user record → ML-KEM public key."""

from __future__ import annotations

from sqlite3 import Row

from database import get_db


class IdentityError(Exception):
    pass


def list_users() -> list[Row]:
    return get_db().execute(
        "SELECT id, name, student_id, email, created_at FROM users ORDER BY student_id"
    ).fetchall()


def get_user_by_student_id(student_id: str) -> Row | None:
    return get_db().execute(
        "SELECT * FROM users WHERE student_id = ?",
        (student_id,),
    ).fetchone()


def get_user_by_id(user_pk: int) -> Row | None:
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_pk,)).fetchone()


def require_user(student_id: str) -> Row:
    user = get_user_by_student_id(student_id)
    if user is None:
        raise IdentityError("Unknown recipient identity.")
    return user
