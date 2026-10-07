from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import create_app


@pytest.fixture()
def app(tmp_path):
    keys = tmp_path / "keys"
    enc = tmp_path / "encrypted"
    uploads = tmp_path / "uploads"
    db = tmp_path / "instance" / "test.db"
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(db),
            "KEYS_DIR": str(keys),
            "ENCRYPTED_DIR": str(enc),
            "UPLOAD_DIR": str(uploads),
        }
    )
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def login(client, student_id: str):
    return client.post(f"/login/{student_id}", follow_redirects=True)
