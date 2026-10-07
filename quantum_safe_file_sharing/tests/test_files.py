from io import BytesIO
from pathlib import Path

from services import file_service
from services.file_service import AccessDenied, FileServiceError


def test_encrypt_decrypt_same_bytes(app):
    original = b"hello from 23MIC0006"
    with app.app_context():
        stored = file_service.encrypt_and_store(
            "23MIC0006", "23MIC0007", "note.txt", original
        )
        result = file_service.decrypt_for_user(stored["file_id"], "23MIC0007")
        assert result["plaintext"] == original
        assert result["integrity"] == "VERIFIED"
        assert result["original_sha256"] == result["recovered_sha256"]


def test_recipient_can_decrypt_outsider_cannot(app):
    original = b"only rahul should read this"
    with app.app_context():
        stored = file_service.encrypt_and_store(
            "23MIC0006", "23MIC0007", "secret.txt", original
        )
        ok = file_service.decrypt_for_user(stored["file_id"], "23MIC0007")
        assert ok["plaintext"] == original
        try:
            file_service.decrypt_for_user(stored["file_id"], "23MIC0008")
            assert False, "Ananya must not decrypt Rahul's file"
        except AccessDenied:
            pass


def test_invalid_recipient(app):
    with app.app_context():
        try:
            file_service.encrypt_and_store("23MIC0006", "UNKNOWN", "a.txt", b"abc")
            assert False, "expected invalid recipient"
        except FileServiceError as exc:
            assert exc.code == "invalid_recipient"


def test_tampered_ciphertext(app):
    original = b"integrity check payload"
    with app.app_context():
        stored = file_service.encrypt_and_store(
            "23MIC0006", "23MIC0007", "report.txt", original
        )
        package_dir = Path(app.config["ENCRYPTED_DIR"]) / stored["file_id"]
        blob_path = package_dir / "encrypted.bin"
        data = bytearray(blob_path.read_bytes())
        data[0] ^= 0xFF
        blob_path.write_bytes(bytes(data))
        try:
            file_service.decrypt_for_user(stored["file_id"], "23MIC0007")
            assert False, "tampered ciphertext must fail"
        except FileServiceError as exc:
            assert exc.code == "decrypt_failed"


def test_http_authorization(client):
    login = client.post("/login/23MIC0006", follow_redirects=True)
    assert login.status_code == 200
    response = client.post(
        "/api/send",
        data={
            "recipient_id": "23MIC0007",
            "file": (BytesIO(b"project bytes"), "project.txt"),
        },
    )
    assert response.status_code == 200
    file_id = response.get_json()["file_id"]

    denied = client.post(f"/api/files/{file_id}/decrypt")
    assert denied.status_code == 403
    body = denied.get_json()
    assert body["code"] == "access_denied"

    client.post("/logout")
    client.post("/login/23MIC0007")
    allowed = client.post(f"/api/files/{file_id}/decrypt")
    assert allowed.status_code == 200
    payload = allowed.get_json()
    assert payload["integrity"] == "VERIFIED"
