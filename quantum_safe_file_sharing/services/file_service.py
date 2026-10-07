"""Envelope encryption, package storage, and recipient authorization."""

from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

from config import ALLOWED_EXTENSIONS, FILE_ENCRYPTION, KDF_ALGORITHM, KEM_ALGORITHM, KEY_WRAP, MAX_CONTENT_LENGTH
from crypto.key_manager import load_private_key_for_identity, load_public_key_from_b64
from crypto.pqc import encapsulate, decapsulate
from crypto.symmetric import (
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes_key,
    sha256_hex,
    unwrap_file_key,
    wrap_file_key,
)
from database import get_db
from services import activity_service, identity_service

logger = logging.getLogger(__name__)


class FileServiceError(Exception):
    def __init__(self, message: str, code: str = "error"):
        super().__init__(message)
        self.code = code


class AccessDenied(FileServiceError):
    def __init__(self, message: str = "Your identity is not authorized to decrypt this file."):
        super().__init__(message, code="access_denied")


def associated_data(file_id: str, recipient_id: str, original_filename: str) -> bytes:
    return f"{file_id}|{recipient_id}|{original_filename}".encode("utf-8")


def validate_upload(filename: str, data: bytes) -> str:
    if not filename:
        raise FileServiceError("No file was selected.", "empty_upload")
    if not data:
        raise FileServiceError("The uploaded file is empty.", "empty_upload")
    if len(data) > MAX_CONTENT_LENGTH:
        raise FileServiceError("The file exceeds the 10 MB limit.", "too_large")
    safe_name = Path(filename).name
    if safe_name != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise FileServiceError("Invalid filename.", "invalid_filename")
    secured = secure_filename(safe_name)
    if not secured:
        raise FileServiceError("Invalid filename.", "invalid_filename")
    ext = secured.rsplit(".", 1)[-1].lower() if "." in secured else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise FileServiceError(
            "Unsupported file type. Allowed types include PDF, images, documents, and text.",
            "unsupported_type",
        )
    return secured


def encrypt_and_store(
    sender_id: str,
    recipient_id: str,
    original_filename: str,
    plaintext: bytes,
    allow_self: bool = False,
) -> dict:
    filename = validate_upload(original_filename, plaintext)
    if sender_id == recipient_id and not allow_self:
        raise FileServiceError("Choose a different recipient identity.", "invalid_recipient")

    try:
        recipient = identity_service.require_user(recipient_id)
        sender = identity_service.require_user(sender_id)
    except identity_service.IdentityError as exc:
        raise FileServiceError(str(exc), "invalid_recipient") from exc

    file_id = str(uuid.uuid4())
    encrypted_dir = Path(current_app.config["ENCRYPTED_DIR"]) / file_id
    encrypted_dir.mkdir(parents=True, exist_ok=False)

    aad = associated_data(file_id, recipient["student_id"], filename)
    file_key = generate_aes_key()
    file_nonce, ciphertext = encrypt_aes_gcm(file_key, plaintext, aad)

    public_key = load_public_key_from_b64(recipient["public_key"])
    shared_secret, kem_ciphertext = encapsulate(public_key)
    wrapped = wrap_file_key(shared_secret, file_key, aad)

    metadata = {
        "file_id": file_id,
        "original_filename": filename,
        "sender_id": sender["student_id"],
        "recipient_id": recipient["student_id"],
        "algorithms": {
            "kem": KEM_ALGORITHM,
            "kdf": KDF_ALGORITHM,
            "file_enc": FILE_ENCRYPTION,
            "key_wrap": KEY_WRAP,
        },
        "file_nonce_b64": base64.b64encode(file_nonce).decode("ascii"),
        "wrap_nonce_b64": base64.b64encode(wrapped["nonce"]).decode("ascii"),
        "wrapped_key_b64": base64.b64encode(wrapped["wrapped_key"]).decode("ascii"),
        "kem_ciphertext_b64": base64.b64encode(kem_ciphertext).decode("ascii"),
        "hkdf_salt_b64": base64.b64encode(wrapped["salt"]).decode("ascii"),
        "original_sha256": sha256_hex(plaintext),
        "ciphertext_sha256": sha256_hex(ciphertext),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "size_bytes": len(plaintext),
    }

    encrypted_path = encrypted_dir / "encrypted.bin"
    metadata_path = encrypted_dir / "metadata.json"
    encrypted_path.write_bytes(ciphertext)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    db = get_db()
    db.execute(
        """
        INSERT INTO files (id, original_filename, sender_id, recipient_id, encrypted_path, metadata_path, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            filename,
            sender["student_id"],
            recipient["student_id"],
            str(encrypted_path),
            str(metadata_path),
            metadata["created_at"],
            "protected",
        ),
    )
    db.commit()

    activity_service.log_event(sender_id, "File encrypted", file_id, filename)
    activity_service.log_event(sender_id, "ML-KEM encapsulation completed", file_id, KEM_ALGORITHM)
    activity_service.log_event(sender_id, f"Package assigned to {recipient_id}", file_id, recipient["name"])

    logger.info("Encrypted package %s from %s to %s", file_id, sender_id, recipient_id)
    return {
        "file_id": file_id,
        "original_filename": filename,
        "size_bytes": len(plaintext),
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "recipient_name": recipient["name"],
        "algorithms": metadata["algorithms"],
        "original_sha256": metadata["original_sha256"],
        "ciphertext_sha256": metadata["ciphertext_sha256"],
        "created_at": metadata["created_at"],
    }


def _load_package(file_id: str) -> tuple:
    row = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if row is None:
        raise FileServiceError("Encrypted package not found.", "missing_file")
    metadata_path = Path(row["metadata_path"])
    encrypted_path = Path(row["encrypted_path"])
    if not metadata_path.is_file() or not encrypted_path.is_file():
        raise FileServiceError("Encrypted package is incomplete or missing.", "missing_file")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FileServiceError("Encrypted package metadata is corrupted.", "corrupted") from exc
    ciphertext = encrypted_path.read_bytes()
    return row, metadata, ciphertext


def decrypt_for_user(file_id: str, requester_id: str) -> dict:
    row, metadata, ciphertext = _load_package(file_id)
    recipient_id = row["recipient_id"]

    if requester_id != recipient_id:
        activity_service.log_event(
            requester_id,
            "Access denied",
            file_id,
            "Recipient identity does not match authorized identity.",
        )
        raise AccessDenied()

    try:
        private_key = load_private_key_for_identity(
            requester_id, Path(current_app.config["KEYS_DIR"])
        )
    except FileNotFoundError as exc:
        activity_service.log_event(requester_id, "Access denied", file_id, str(exc))
        raise AccessDenied("ML-KEM private key unavailable for this identity.") from exc

    activity_service.log_event(requester_id, "Recipient identity verified", file_id, requester_id)

    try:
        kem_ct = base64.b64decode(metadata["kem_ciphertext_b64"])
        shared_secret = decapsulate(private_key, kem_ct)
        aad = associated_data(file_id, recipient_id, metadata["original_filename"])
        file_key = unwrap_file_key(
            shared_secret,
            base64.b64decode(metadata["hkdf_salt_b64"]),
            base64.b64decode(metadata["wrap_nonce_b64"]),
            base64.b64decode(metadata["wrapped_key_b64"]),
            aad,
        )
        plaintext = decrypt_aes_gcm(
            file_key,
            base64.b64decode(metadata["file_nonce_b64"]),
            ciphertext,
            aad,
        )
    except Exception as exc:
        logger.warning("Decryption failed for %s: %s", file_id, exc)
        activity_service.log_event(requester_id, "Decryption failed", file_id, "Corrupted or tampered package")
        raise FileServiceError(
            "Decryption failed. The package may be corrupted or tampered with.",
            "decrypt_failed",
        ) from exc

    recovered_hash = sha256_hex(plaintext)
    original_hash = metadata.get("original_sha256", "")
    integrity = "VERIFIED" if recovered_hash == original_hash else "MISMATCH"

    activity_service.log_event(requester_id, "ML-KEM decapsulation completed", file_id, KEM_ALGORITHM)
    activity_service.log_event(requester_id, "File decrypted", file_id, metadata["original_filename"])

    return {
        "file_id": file_id,
        "original_filename": metadata["original_filename"],
        "plaintext": plaintext,
        "original_sha256": original_hash,
        "recovered_sha256": recovered_hash,
        "ciphertext_sha256": sha256_hex(ciphertext),
        "integrity": integrity,
        "sender_id": row["sender_id"],
        "recipient_id": recipient_id,
    }


def list_received(student_id: str) -> list:
    rows = get_db().execute(
        """
        SELECT id, original_filename, sender_id, recipient_id, created_at, status
        FROM files
        WHERE recipient_id = ?
        ORDER BY created_at DESC
        """,
        (student_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def list_all_packages() -> list:
    rows = get_db().execute(
        """
        SELECT id, original_filename, sender_id, recipient_id, created_at, status
        FROM files
        ORDER BY created_at DESC
        """
    ).fetchall()
    return [dict(r) for r in rows]


def count_protected() -> int:
    row = get_db().execute("SELECT COUNT(*) AS n FROM files").fetchone()
    return int(row["n"]) if row else 0


def count_received(student_id: str) -> int:
    row = get_db().execute(
        "SELECT COUNT(*) AS n FROM files WHERE recipient_id = ?",
        (student_id,),
    ).fetchone()
    return int(row["n"]) if row else 0
