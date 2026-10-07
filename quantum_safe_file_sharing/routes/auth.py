from __future__ import annotations

from functools import wraps

from flask import Blueprint, flash, g, jsonify, redirect, render_template, request, session, url_for

from services import identity_service

bp = Blueprint("auth", __name__)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.current_user is None:
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Demo session required.", "code": "auth"}), 401
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


@bp.route("/login")
def login():
    if g.current_user is not None:
        return redirect(url_for("dashboard.index"))
    users = identity_service.list_users()
    return render_template("login.html", users=users)


@bp.post("/login/<student_id>")
def login_as(student_id: str):
    user = identity_service.get_user_by_student_id(student_id)
    if user is None:
        flash("Unknown demo identity.", "error")
        return redirect(url_for("auth.login"))
    session.clear()
    session["student_id"] = user["student_id"]
    return redirect(url_for("dashboard.index"))


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
