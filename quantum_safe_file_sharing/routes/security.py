from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify, render_template, request

from routes.auth import login_required
from services import activity_service, file_service, identity_service
from services.file_service import AccessDenied, FileServiceError

logger = logging.getLogger(__name__)
bp = Blueprint("security", __name__)


@bp.route("/security")
@login_required
def security_page():
    users = identity_service.list_users()
    packages = file_service.list_all_packages()
    return render_template("security.html", users=users, packages=packages)


@bp.route("/activity")
@login_required
def activity_page():
    events = activity_service.list_events()
    return render_template("activity.html", events=events)


@bp.route("/about")
@login_required
def about_page():
    return render_template("about.html")


@bp.post("/api/security/simulate")
@login_required
def api_simulate():
    recipient_id = (request.form.get("recipient_id") or g.current_user["student_id"]).strip()
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"ok": False, "error": "Select a file for the integrity demonstration.", "code": "empty_upload"}), 400
    data = upload.read()
    allow_self = recipient_id == g.current_user["student_id"]
    try:
        stored = file_service.encrypt_and_store(
            g.current_user["student_id"],
            recipient_id,
            upload.filename or "",
            data,
            allow_self=allow_self,
        )
        decrypted = file_service.decrypt_for_user(stored["file_id"], g.current_user["student_id"])
    except AccessDenied as exc:
        return jsonify(
            {
                "ok": False,
                "code": "access_denied",
                "title": "ACCESS DENIED",
                "error": str(exc),
                "encrypted": True,
            }
        ), 403
    except FileServiceError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), 400
    except Exception:
        logger.exception("Simulation failed")
        return jsonify({"ok": False, "error": "Simulation failed. See server logs.", "code": "server"}), 500

    return jsonify(
        {
            "ok": True,
            "file_id": stored["file_id"],
            "original_filename": stored["original_filename"],
            "original_sha256": decrypted["original_sha256"],
            "recovered_sha256": decrypted["recovered_sha256"],
            "ciphertext_sha256": decrypted["ciphertext_sha256"],
            "integrity": decrypted["integrity"],
            "recipient_id": recipient_id,
        }
    )
