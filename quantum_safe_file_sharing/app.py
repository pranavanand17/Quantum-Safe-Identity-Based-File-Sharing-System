"""Quantum-Safe Identity-Based File Sharing System — local Flask entrypoint."""

from __future__ import annotations

import logging
from pathlib import Path

from flask import Flask, g, render_template, session
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config, ENCRYPTED_DIR, KEYS_DIR, UPLOAD_DIR, ensure_directories
from database import close_db, init_db
from routes.auth import bp as auth_bp
from routes.dashboard import bp as dashboard_bp
from routes.files import bp as files_bp
from routes.security import bp as security_bp
from services import identity_service


def create_app(test_config: dict | None = None) -> Flask:
    ensure_directories()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    app.config["ENCRYPTED_DIR"] = str(ENCRYPTED_DIR)
    app.config["KEYS_DIR"] = str(KEYS_DIR)
    app.config["UPLOAD_DIR"] = str(UPLOAD_DIR)

    if test_config:
        app.config.update(test_config)
        for key in ("ENCRYPTED_DIR", "KEYS_DIR", "UPLOAD_DIR"):
            Path(app.config[key]).mkdir(parents=True, exist_ok=True)
        Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(security_bp)
    app.teardown_appcontext(close_db)

    @app.before_request
    def load_current_user():
        student_id = session.get("student_id")
        g.current_user = identity_service.get_user_by_student_id(student_id) if student_id else None

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return (
            render_template(
                "error.html",
                title="File too large",
                message="Uploads are limited to 10 MB in this prototype.",
            ),
            413,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return (
            render_template(
                "error.html",
                title="Not found",
                message="The requested page or resource does not exist.",
            ),
            404,
        )

    @app.errorhandler(500)
    def server_error(_error):
        return (
            render_template(
                "error.html",
                title="Something went wrong",
                message="An internal error occurred. Technical details were written to the server log.",
            ),
            500,
        )

    init_db(app)
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
