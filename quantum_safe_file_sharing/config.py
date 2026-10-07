"""Application configuration for the local academic prototype."""

from __future__ import annotations

import os
import secrets
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
KEYS_DIR = DATA_DIR / "keys"
DATABASE_PATH = INSTANCE_DIR / "database.db"

MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {
    "txt",
    "md",
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "csv",
    "json",
    "doc",
    "docx",
    "zip",
    "py",
    "c",
    "cpp",
    "h",
}

KEM_ALGORITHM = "ML-KEM-768"
FILE_ENCRYPTION = "AES-256-GCM"
KEY_WRAP = "AES-256-GCM"
KDF_ALGORITHM = "HKDF-SHA256"

DEMO_USERS = (
    {
        "name": "Pranav Anand",
        "student_id": "23MIC0006",
        "email": "pranav@student.local",
    },
    {
        "name": "Rahul Kumar",
        "student_id": "23MIC0007",
        "email": "rahul@student.local",
    },
    {
        "name": "Ananya Sharma",
        "student_id": "23MIC0008",
        "email": "ananya@student.local",
    },
)


def ensure_directories() -> None:
    for path in (INSTANCE_DIR, DATA_DIR, UPLOAD_DIR, ENCRYPTED_DIR, KEYS_DIR):
        path.mkdir(parents=True, exist_ok=True)


def load_secret_key() -> str:
    env_key = os.environ.get("FLASK_SECRET_KEY")
    if env_key:
        return env_key
    ensure_directories()
    secret_path = INSTANCE_DIR / "secret_key"
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()
    generated = secrets.token_hex(32)
    secret_path.write_text(generated, encoding="utf-8")
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    return generated


class Config:
    SECRET_KEY = load_secret_key()
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH
    DATABASE = str(DATABASE_PATH)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    TEMPLATES_AUTO_RELOAD = True
