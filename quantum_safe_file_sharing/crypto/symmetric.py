"""AES-256-GCM, HKDF key wrapping, and SHA-256 helpers."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_SIZE = 12
KEY_SIZE = 32
SALT_SIZE = 16
HKDF_INFO = b"qsfs-mlkem-aes-wrap-v1"


def generate_aes_key() -> bytes:
    return os.urandom(KEY_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def sha256_hex(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def encrypt_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes) -> tuple[bytes, bytes]:
    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_aes_gcm(
    key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes
) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def derive_wrap_key(shared_secret: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def wrap_file_key(shared_secret: bytes, file_key: bytes, associated_data: bytes) -> dict[str, bytes]:
    salt = os.urandom(SALT_SIZE)
    wrap_key = derive_wrap_key(shared_secret, salt)
    nonce, wrapped = encrypt_aes_gcm(wrap_key, file_key, associated_data)
    return {"salt": salt, "nonce": nonce, "wrapped_key": wrapped}


def unwrap_file_key(
    shared_secret: bytes,
    salt: bytes,
    nonce: bytes,
    wrapped_key: bytes,
    associated_data: bytes,
) -> bytes:
    wrap_key = derive_wrap_key(shared_secret, salt)
    return decrypt_aes_gcm(wrap_key, nonce, wrapped_key, associated_data)
