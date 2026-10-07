from crypto.pqc import decapsulate, encapsulate, generate_keypair
from crypto.symmetric import decrypt_aes_gcm, encrypt_aes_gcm, generate_aes_key, sha256_hex, unwrap_file_key, wrap_file_key


def test_key_generation_and_kem_roundtrip():
    private_key, public_key = generate_keypair()
    shared, ciphertext = encapsulate(public_key)
    recovered = decapsulate(private_key, ciphertext)
    assert shared == recovered
    assert len(shared) == 32


def test_file_encryption_roundtrip():
    original = b"quantum-safe prototype payload"
    key = generate_aes_key()
    nonce, ciphertext = encrypt_aes_gcm(key, original, b"aad")
    assert ciphertext != original
    recovered = decrypt_aes_gcm(key, nonce, ciphertext, b"aad")
    assert recovered == original
    assert sha256_hex(original) == sha256_hex(recovered)


def test_key_wrap_roundtrip():
    file_key = generate_aes_key()
    private_key, public_key = generate_keypair()
    shared, _ct = encapsulate(public_key)
    wrapped = wrap_file_key(shared, file_key, b"wrap-aad")
    opened = unwrap_file_key(
        shared, wrapped["salt"], wrapped["nonce"], wrapped["wrapped_key"], b"wrap-aad"
    )
    assert opened == file_key
