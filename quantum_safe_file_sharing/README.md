# Quantum-Safe Identity-Based File Sharing System

Student: **Pranav Anand**  
Register Number: **23MIC0006**

## Abstract

This project is a local educational web application that demonstrates secure file sharing using **identity-based access and key management combined with post-quantum cryptography**. A recipient is selected by student identity. That identity is resolved to a stored ML-KEM public key. The file is encrypted with AES-256-GCM. The file-encryption key is protected with **ML-KEM-768** key encapsulation (NIST FIPS 203), using the maintained implementation in the Python `cryptography` library.

ML-KEM is **not** identity-based encryption (IBE). This prototype maps identities to public keys, then uses ML-KEM as a KEM.

## Features

- Demo sign-in as one of three local student identities
- Identity directory: student ID → user record → ML-KEM public key
- Envelope encryption (AES-256-GCM + ML-KEM-768 + HKDF-SHA256 key wrap)
- Animated send/decrypt pipelines for presentations
- Received-file vault with server-side recipient authorization
- Unauthorized-access demonstration (authorization check, not an attack tool)
- SHA-256 integrity comparison before/after recovery
- Activity timeline of security events
- Architecture/security explainer page
- Automated tests for crypto, identity, authorization, and tampering

## Architecture

```
IDENTITY
  → user record / identity-to-public-key mapping
  → recipient public key
  → ML-KEM-768 encapsulation
  → shared secret
  → HKDF-SHA256 wrap of a random AES-256 file key
  → AES-256-GCM file encryption
```

Private ML-KEM seeds stay on disk under `data/keys/`. They are **not** stored in SQLite. Encrypted packages live under `data/encrypted/<file_id>/`.

## Technology stack

- Python 3.12+ (developed against Python 3.12 in the project virtualenv)
- Flask, SQLite
- `cryptography` for ML-KEM-768, AES-256-GCM, HKDF-SHA256, and SHA-256
- HTML, CSS, vanilla JavaScript

## Cryptographic algorithms

| Role | Algorithm |
| --- | --- |
| File encryption | AES-256-GCM (random 256-bit key, 96-bit nonce, identity-bound AAD) |
| Post-quantum KEM | ML-KEM-768 (`cryptography.hazmat.primitives.asymmetric.mlkem`) |
| Key derivation | HKDF-SHA256 over the ML-KEM shared secret |
| File-key wrap | AES-256-GCM using the HKDF output |
| Integrity demo | SHA-256 of original plaintext vs recovered plaintext |

No cryptographic primitives are implemented by hand.

## How identity-based access works

Demo users are stored in SQLite. Selecting recipient `23MIC0007` looks up Rahul Kumar and loads his ML-KEM public key. That lookup is the identity-based portion of the demo. Access control on decrypt compares the signed-in student ID with the package `recipient_id`. Hiding files in the UI is not sufficient; the API refuses unauthorized decryption.

## How ML-KEM is used

The sender encapsulates to the recipient public key, producing a shared secret and a KEM ciphertext. The ciphertext is stored in package metadata. The recipient loads their local private seed and decapsulates to recover the same shared secret. That secret is never shown in the UI and is not written to the database.

## How AES-256-GCM is used

A random file key encrypts the uploaded bytes. Associated data binds the ciphertext to `file_id`, recipient identity, and original filename. After ML-KEM, HKDF derives a wrapping key that encrypts the file key. Plaintext files are not retained after a successful send.

## Installation

From the project directory (Linux/WSL recommended with the included `.venv`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell, if you create a native venv:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Set a Flask secret if you wish:

```bash
export FLASK_SECRET_KEY="a-long-random-value"
```

If the variable is unset, the app writes a generated key to `instance/secret_key` (gitignored). That is for local demonstration only.

## Running the application

```bash
python app.py
```

Open http://127.0.0.1:5000

Startup is idempotent: demo users and key material are created only if they are missing.

## Demo users

This is **demo authentication**, not production login. There are no passwords.

| Name | Student ID | Email |
| --- | --- | --- |
| Pranav Anand | 23MIC0006 | pranav@student.local |
| Rahul Kumar | 23MIC0007 | rahul@student.local |
| Ananya Sharma | 23MIC0008 | ananya@student.local |

## Demo flow

1. Login as Pranav
2. Send a file to Rahul
3. Watch the encryption pipeline
4. Login as Rahul
5. Open Received Files
6. Decrypt the file
7. Verify SHA-256 integrity
8. Attempt access as Ananya (or use Attempt Unauthorized Access while still Pranav)
9. Observe access denial

## Tests

```bash
python -m pytest -q
```

## Security considerations

Sensible prototype controls:

- OS CSPRNG via `os.urandom` / library APIs
- Authenticated encryption (AES-GCM)
- Backend authorization on decrypt and download tokens
- Server-generated file IDs and `secure_filename` path checks
- 10 MB upload limit and extension allow-list
- No plaintext secrets in HTML
- No private keys in SQLite
- `.gitignore` excludes keys, uploads, encrypted packages, the database, and env files

This remains a **local academic prototype**. Demo identity selection is not real authentication. Session cookies are not configured for HTTPS deployment. Key files use restrictive permissions where the OS allows it.

## Limitations

- Demo login has no passwords, MFA, or institutional SSO
- Keys live unencrypted on the local filesystem (acceptable only for a lab demo)
- Single-process download tokens are in memory
- Not a full IBE construction (Boneh–Franklin or similar)
- Not a production file-sharing product

## Future improvements

- Real authentication and audit-grade identity proofing
- Hardware-backed or encrypted key storage
- Streaming encryption for large files
- Optional hybrid KEM (ML-KEM + X25519) if a policy requires it
- Multi-recipient packages and revocation

## Project layout

See `app.py`, `crypto/`, `services/`, `routes/`, `templates/`, and `tests/`.
