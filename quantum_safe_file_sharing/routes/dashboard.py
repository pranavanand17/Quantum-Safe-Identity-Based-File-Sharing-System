from __future__ import annotations

from flask import Blueprint, g, render_template

from routes.auth import login_required
from services import file_service, identity_service

bp = Blueprint("dashboard", __name__)


@bp.route("/")
@login_required
def index():
    users = identity_service.list_users()
    return render_template(
        "dashboard.html",
        protected_count=file_service.count_protected(),
        received_count=file_service.count_received(g.current_user["student_id"]),
        users=users,
    )
