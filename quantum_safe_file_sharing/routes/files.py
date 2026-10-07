from __future__ import annotations

import logging
import secrets
import time

from flask import Blueprint, g, jsonify, render_template, request, send_file
from io import BytesIO

from routes.auth import login_required
from services import file_service, identity_service
from services.file_service import AccessDenied, FileServiceError

logger = logging.getLogger(__name__)
bp = Blueprint("files", __name__)

_DOWNLOADS: dict[str, dict] = {}
_TOKEN_TTL = 120


def _purge_downloads() -> None:
    now = time.time()
    expired = [k for k, v in _DOWNLOADS.items() if now - v["created"] > _TOKEN_TTL]
    for key in expired:
        _DOWNLOADS.pop(key, None)


@bp.route("/send")
@login_required
def send_page():
    users = [
        u
        for u in identity_service.list_users()
        if u["student_id"] != g.current_user["student_id"]
    ]
    return render_template("send.html", recipients=users)


@bp.route("/received")
@login_required
def received_page():
    packages = file_service.list_received(g.current_user["student_id"])
    others = file_service.list_all_packages()
    unauthorized_targets = [
        p for p in others if p["recipient_id"] != g.current_user["student_id"]
    ]
    return render_template(
        "received.html",
        packages=packages,
        unauthorized_targets=unauthorized_targets,
    )


@bp.post("/api/send")
@login_required
def api_send():
    recipient_id = (request.form.get("recipient_id") or "").strip()
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"ok": False, "error": "Select a file to protect.", "code": "empty_upload"}), 400
    data = upload.read()
    try:
        result = file_service.encrypt_and_store(
            g.current_user["student_id"],
            recipient_id,
            upload.filename or "",
            data,
        )
    except identity_service.IdentityError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": "invalid_recipient"}), 400
    except FileServiceError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), 400
    except Exception:
        logger.exception("Unexpected error during encryption")
        return jsonify({"ok": False, "error": "Secure send failed. See server logs.", "code": "server"}), 500
    return jsonify({"ok": True, **result})


@bp.post("/api/files/<file_id>/decrypt")
@login_required
def api_decrypt(file_id: str):
    try:
        result = file_service.decrypt_for_user(file_id, g.current_user["student_id"])
    except AccessDenied as exc:
        return jsonify(
            {
                "ok": False,
                "code": "access_denied",
                "title": "ACCESS DENIED",
                "error": str(exc),
                "reason": "Recipient identity does not match authorized identity.",
                "detail": "ML-KEM private key unavailable for this identity.",
            }
        ), 403
    except FileServiceError as exc:
        status = 404 if exc.code == "missing_file" else 400
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), status
    except Exception:
        logger.exception("Unexpected error during decryption")
        return jsonify({"ok": False, "error": "Decryption failed. See server logs.", "code": "server"}), 500

    _purge_downloads()
    token = secrets.token_urlsafe(24)
    _DOWNLOADS[token] = {
        "created": time.time(),
        "owner": g.current_user["student_id"],
        "filename": result["original_filename"],
        "data": result["plaintext"],
    }
    payload = {k: v for k, v in result.items() if k != "plaintext"}
    payload["ok"] = True
    payload["download_token"] = token
    return jsonify(payload)


@bp.get("/api/files/download/<token>")
@login_required
def api_download(token: str):
    _purge_downloads()
    item = _DOWNLOADS.get(token)
    if item is None or item["owner"] != g.current_user["student_id"]:
        return jsonify({"ok": False, "error": "Download expired or is not authorized.", "code": "access_denied"}), 403
    data = item["data"]
    filename = item["filename"]
    _DOWNLOADS.pop(token, None)
    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )


@bp.post("/api/files/<file_id>/unauthorized")
@login_required
def api_unauthorized(file_id: str):
    try:
        file_service.decrypt_for_user(file_id, g.current_user["student_id"])
    except AccessDenied as exc:
        return jsonify(
            {
                "ok": False,
                "code": "access_denied",
                "title": "ACCESS DENIED",
                "error": str(exc),
                "reason": "Recipient identity does not match authorized identity.",
                "detail": "ML-KEM private key unavailable for this identity.",
            }
        ), 403
    except FileServiceError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code}), 400
    return jsonify(
        {
            "ok": True,
            "note": "Current identity is the authorized recipient, so decryption is allowed.",
        }
    )
