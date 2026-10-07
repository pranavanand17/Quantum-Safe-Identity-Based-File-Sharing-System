"""ML-KEM-768 key encapsulation via the cryptography library.

This module does not implement Identity-Based Encryption. It performs
NIST ML-KEM encapsulation/decapsulation on keys that the identity
service associates with a user record.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

ALGORITHM = "ML-KEM-768"


def generate_keypair() -> tuple[MLKEM768PrivateKey, MLKEM768PublicKey]:
    private_key = MLKEM768PrivateKey.generate()
    return private_key, private_key.public_key()


def serialize_public_key(public_key: MLKEM768PublicKey) -> bytes:
    return public_key.public_bytes_raw()


def serialize_private_seed(private_key: MLKEM768PrivateKey) -> bytes:
    return private_key.private_bytes_raw()


def load_public_key(raw: bytes) -> MLKEM768PublicKey:
    return MLKEM768PublicKey.from_public_bytes(raw)


def load_private_key(seed: bytes) -> MLKEM768PrivateKey:
    return MLKEM768PrivateKey.from_seed_bytes(seed)


def encapsulate(public_key: MLKEM768PublicKey) -> tuple[bytes, bytes]:
    """Return (shared_secret, kem_ciphertext)."""
    return public_key.encapsulate()


def decapsulate(private_key: MLKEM768PrivateKey, ciphertext: bytes) -> bytes:
    return private_key.decapsulate(ciphertext)
