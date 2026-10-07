"""Filesystem storage for ML-KEM private seeds. Public keys live in SQLite."""

from __future__ import annotations

import os
from pathlib import Path

from crypto.pqc import (
    generate_keypair,
    serialize_private_seed,
    serialize_public_key,
    load_private_key,
    load_public_key,
)


def _key_path(student_id: str, keys_dir: Path) -> Path:
    safe_id = "".join(ch for ch in student_id if ch.isalnum())
    if not safe_id:
        raise ValueError("Invalid student identity for key storage.")
    return keys_dir / f"{safe_id}.mlkem768.seed"


def ensure_user_keys(student_id: str, keys_dir: Path) -> tuple[str, str]:
    """Create keys if missing. Returns (public_key_b64, private_key_reference)."""
    import base64

    keys_dir.mkdir(parents=True, exist_ok=True)
    path = _key_path(student_id, keys_dir)
    if path.exists():
        private_key = load_private_key(path.read_bytes())
        public_b64 = base64.b64encode(serialize_public_key(private_key.public_key())).decode("ascii")
        return public_b64, str(path.name)

    private_key, public_key = generate_keypair()
    seed = serialize_private_seed(private_key)
    path.write_bytes(seed)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    public_b64 = base64.b64encode(serialize_public_key(public_key)).decode("ascii")
    return public_b64, str(path.name)


def load_private_key_for_identity(student_id: str, keys_dir: Path):
    path = _key_path(student_id, keys_dir)
    if not path.is_file():
        raise FileNotFoundError(f"ML-KEM private key unavailable for identity {student_id}.")
    return load_private_key(path.read_bytes())


def load_public_key_from_b64(public_key_b64: str):
    import base64

    return load_public_key(base64.b64decode(public_key_b64.encode("ascii")))
