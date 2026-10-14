
import base64
import binascii
import io
import json
import os
import secrets
import time
from threading import Lock

import qrcode
from flask import (
    Flask, render_template, jsonify, request,
    send_file, abort
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

PUBLIC_URL = "https://cover-treble-unmoving.ngrok-free.dev"

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_ENVELOPE_SIZE = 16 * 1024 * 1024
PAIRING_TTL = 120
TRANSFER_TTL = 600

# Base64-encoded public-key lengths are checked after decoding.
ML_KEM_PUBLIC_KEY_BYTES = 1184
ML_DSA_PUBLIC_KEY_BYTES = 1952

app.config["MAX_CONTENT_LENGTH"] = MAX_ENVELOPE_SIZE

TRANSFER_DIR = os.path.join(app.root_path, "data", "transfers")
os.makedirs(TRANSFER_DIR, exist_ok=True)

lock = Lock()
pairing_sessions = {}
transfers = {}


def public_url():
    return PUBLIC_URL.rstrip("/")


def decode_key(value, expected_length):
    if not isinstance(value, str):
        return None

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return None

    return decoded if len(decoded) == expected_length else None


def paired_session(token):
    session = pairing_sessions.get(token)
    return session if session and session["status"] == "paired" else None


def cleanup_transfers():
    now = time.time()

    with lock:
        expired = [
            transfer_id
            for transfer_id, transfer in transfers.items()
            if transfer["expires_at"] <= now
        ]

        for transfer_id in expired:
            transfer = transfers.pop(transfer_id)
            try:
                os.remove(transfer["path"])
            except FileNotFoundError:
                pass


def transfer_summary(transfer):
    return {
        "id": transfer["id"],
        "filename": transfer["filename"],
        "size": transfer["size"],
        "status": transfer["status"],
        "direction": transfer["direction"],
    }


def validate_envelope(raw, token, direction, session):
    """Validate envelope structure and visible metadata, not its signature."""
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "The uploaded payload is not a valid encrypted envelope."

    if not isinstance(envelope, dict) or envelope.get("version") != 1:
        return None, "Unsupported encrypted-envelope version."

    required_strings = (
        "filename", "type", "senderIdentity", "recipientIdentity",
        "token", "salt", "iv", "kemCiphertext", "ciphertext", "signature",
    )

    if any(not isinstance(envelope.get(k), str) for k in required_strings):
        return None, "The encrypted envelope is incomplete."

    filename = secure_filename(envelope["filename"])
    if not filename:
        return None, "Invalid filename."

    size = envelope.get("size")
    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        return None, "The original file must be 10 MB or smaller."

    if envelope["token"] != token:
        return None, "The envelope belongs to a different pairing session."

    device_name = session["device_name"]

    if direction == "pc_to_phone":
        expected_sender = "This computer"
        expected_recipient = device_name
    else:
        expected_sender = device_name
        expected_recipient = "This computer"

    if (
        envelope["senderIdentity"] != expected_sender
        or envelope["recipientIdentity"] != expected_recipient
    ):
        return None, "The envelope identity does not match this pairing."

    # Reject malformed or obviously incomplete cryptographic fields.
    if len(envelope["salt"]) < 20 or len(envelope["iv"]) < 12:
        return None, "Invalid encryption parameters."

    try:
        salt = base64.b64decode(envelope["salt"], validate=True)
        iv = base64.b64decode(envelope["iv"], validate=True)
        kem_ciphertext = base64.b64decode(
            envelope["kemCiphertext"], validate=True
        )
        ciphertext = base64.b64decode(
            envelope["ciphertext"], validate=True
        )
        signature = base64.b64decode(
            envelope["signature"], validate=True
        )
    except (ValueError, binascii.Error):
        return None, "Invalid encoded cryptographic data."

    if len(salt) != 16 or len(iv) != 12:
        return None, "Invalid salt or nonce length."

    # FIPS 203 ML-KEM-768 encapsulation ciphertext is 1088 bytes.
    if len(kem_ciphertext) != 1088:
        return None, "Invalid ML-KEM-768 ciphertext length."

    # AES-GCM appends a 16-byte authentication tag.
    if len(ciphertext) < 16:
        return None, "Encrypted file is incomplete."

    # ML-DSA-65 signatures are 3309 bytes for this parameter set.
    if len(signature) != 3309:
        return None, "Invalid ML-DSA-65 signature length."

    envelope["filename"] = filename
    return envelope, None


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/pairing")
def create_pairing():
    data = request.get_json(silent=True) or {}

    pc_kem_public = data.get("pc_kem_public_key")
    pc_sign_public = data.get("pc_sign_public_key")

    if not decode_key(pc_kem_public, ML_KEM_PUBLIC_KEY_BYTES):
        return jsonify({"error": "Invalid computer ML-KEM public key."}), 400

    if not decode_key(pc_sign_public, ML_DSA_PUBLIC_KEY_BYTES):
        return jsonify({"error": "Invalid computer ML-DSA public key."}), 400

    now = time.time()
    token = secrets.token_urlsafe(32)

    with lock:
        expired = [
            key for key, value in pairing_sessions.items()
            if value["status"] == "waiting"
            and value["expires_at"] <= now
        ]

        for key in expired:
            pairing_sessions.pop(key, None)

        pairing_sessions[token] = {
            "created_at": now,
            "expires_at": now + PAIRING_TTL,
            "status": "waiting",
            "device_name": None,
            "pc_identity": "This computer",
            "pc_kem_public_key": pc_kem_public,
            "pc_sign_public_key": pc_sign_public,
            "phone_kem_public_key": None,
            "phone_sign_public_key": None,
        }

    return jsonify({
        "token": token,
        "phone_url": f"{public_url()}/pair/{token}",
        "qr_url": f"/api/qr/{token}",
        "expires_in": PAIRING_TTL,
    })


@app.get("/api/qr/<token>")
def pairing_qr(token):
    with lock:
        session = pairing_sessions.get(token)

        if (
            not session
            or session["status"] != "waiting"
            or session["expires_at"] <= time.time()
        ):
            abort(404)

    qr = qrcode.make(f"{public_url()}/pair/{token}")
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)

    return send_file(buffer, mimetype="image/png")


@app.get("/pair/<token>")
def pair_page(token):
    with lock:
        session = pairing_sessions.get(token)
        expired = (
            not session
            or (
                session["status"] == "waiting"
                and session["expires_at"] <= time.time()
            )
        )

    return render_template(
        "pair.html",
        expired=expired,
        token="" if expired else token,
    )


@app.post("/api/pair/<token>")
def confirm_pairing(token):
    data = request.get_json(silent=True) or {}

    device_name = str(data.get("device_name", "My phone")).strip()[:40]
    device_name = device_name or "My phone"

    phone_kem_public = data.get("phone_kem_public_key")
    phone_sign_public = data.get("phone_sign_public_key")

    if not decode_key(phone_kem_public, ML_KEM_PUBLIC_KEY_BYTES):
        return jsonify({"error": "Invalid phone ML-KEM public key."}), 400

    if not decode_key(phone_sign_public, ML_DSA_PUBLIC_KEY_BYTES):
        return jsonify({"error": "Invalid phone ML-DSA public key."}), 400

    with lock:
        session = pairing_sessions.get(token)

        if not session or session["expires_at"] <= time.time():
            return jsonify({
                "error": "Pairing code expired. Generate a new one."
            }), 410

        if session["status"] != "waiting":
            return jsonify({
                "error": "This pairing code has already been used."
            }), 409

        session["status"] = "paired"
        session["device_name"] = device_name
        session["phone_kem_public_key"] = phone_kem_public
        session["phone_sign_public_key"] = phone_sign_public
        session["paired_at"] = time.time()

    return jsonify({
        "status": "paired",
        "device_name": device_name,
    })


@app.get("/api/status/<token>")
def pairing_status(token):
    with lock:
        session = pairing_sessions.get(token)

        if not session:
            return jsonify({"status": "expired"})

        if (
            session["status"] == "waiting"
            and session["expires_at"] <= time.time()
        ):
            pairing_sessions.pop(token, None)
            return jsonify({"status": "expired"})

        return jsonify({
            "status": session["status"],
            "device_name": session["device_name"],
            "pc_identity": session["pc_identity"],
            "pc_kem_public_key": session["pc_kem_public_key"],
            "pc_sign_public_key": session["pc_sign_public_key"],
            "phone_kem_public_key": session["phone_kem_public_key"],
            "phone_sign_public_key": session["phone_sign_public_key"],
        })


def save_transfer(token, uploaded, direction):
    if not uploaded:
        return jsonify({"error": "Choose a file first."}), 400

    raw = uploaded.read()

    if not raw:
        return jsonify({"error": "The encrypted upload is empty."}), 400

    if len(raw) > MAX_ENVELOPE_SIZE:
        return jsonify({"error": "Encrypted upload is too large."}), 413

    with lock:
        session = paired_session(token)

    if not session:
        return jsonify({"error": "Device is no longer paired."}), 403

    envelope, error = validate_envelope(raw, token, direction, session)
    if error:
        return jsonify({"error": error}), 400

    transfer_id = secrets.token_urlsafe(24)
    path = os.path.join(TRANSFER_DIR, secrets.token_hex(16) + ".tbenc")

    try:
        # The server stores the encrypted envelope bytes only.
        with open(path, "wb") as output:
            output.write(raw)

        transfer = {
            "id": transfer_id,
            "pair_token": token,
            "filename": envelope["filename"],
            "size": envelope["size"],
            "path": path,
            "direction": direction,
            "status": "pending",
            "created_at": time.time(),
            "expires_at": time.time() + TRANSFER_TTL,
        }

        with lock:
            if not paired_session(token):
                os.remove(path)
                return jsonify({"error": "Device is no longer paired."}), 403

            transfers[transfer_id] = transfer

    except Exception:
        if os.path.exists(path):
            os.remove(path)
        raise

    return jsonify({
        "id": transfer_id,
        "filename": transfer["filename"],
        "size": transfer["size"],
        "direction": direction,
        "status": "pending",
        "message": "Encrypted transfer request sent for approval.",
    }), 201


@app.post("/api/transfers/<token>")
def upload_file(token):
    with lock:
        if not paired_session(token):
            return jsonify({
                "error": "Pair a phone before sending files."
            }), 403

    return save_transfer(token, request.files.get("file"), "pc_to_phone")


@app.post("/api/phone/upload/<token>")
def phone_upload_file(token):
    with lock:
        if not paired_session(token):
            return jsonify({
                "error": "Pair your phone before sending files."
            }), 403

    return save_transfer(token, request.files.get("file"), "phone_to_pc")


@app.get("/api/transfers/<token>")
def pc_transfers(token):
    with lock:
        if not paired_session(token):
            return jsonify({"error": "Device is not paired."}), 403

    cleanup_transfers()

    with lock:
        items = [
            transfer_summary(t)
            for t in transfers.values()
            if t["pair_token"] == token
        ]

    return jsonify({"transfers": items})


@app.get("/api/phone/transfers/<token>")
def phone_transfers(token):
    with lock:
        if not paired_session(token):
            return jsonify({"error": "Device is not paired."}), 403

    cleanup_transfers()

    with lock:
        items = [
            transfer_summary(t)
            for t in transfers.values()
            if t["pair_token"] == token
            and t["direction"] == "pc_to_phone"
        ]

    return jsonify({"transfers": items})


@app.post("/api/transfers/<transfer_id>/decision")
def decide_transfer(transfer_id):
    data = request.get_json(silent=True) or {}
    token = str(data.get("token", ""))
    decision = data.get("decision")
    actor = data.get("actor")

    if decision not in ("approved", "rejected"):
        return jsonify({"error": "Invalid decision."}), 400

    if actor not in ("pc", "phone"):
        return jsonify({"error": "Invalid recipient identity."}), 400

    cleanup_transfers()

    with lock:
        if not paired_session(token):
            return jsonify({"error": "Device is not paired."}), 403

        transfer = transfers.get(transfer_id)

        if not transfer or transfer["pair_token"] != token:
            return jsonify({"error": "Transfer not found or expired."}), 404

        expected_actor = (
            "phone" if transfer["direction"] == "pc_to_phone" else "pc"
        )

        if actor != expected_actor:
            return jsonify({
                "error": "Only the receiving device can decide this request."
            }), 403

        if transfer["status"] != "pending":
            return jsonify({
                "error": "This request has already been decided."
            }), 409

        transfer["status"] = decision
        transfer["decided_at"] = time.time()

        if decision == "rejected":
            try:
                os.remove(transfer["path"])
            except FileNotFoundError:
                pass

    return jsonify({"status": decision})


@app.get("/api/transfers/<transfer_id>/download")
def download_file(transfer_id):
    token = request.args.get("token", "")

    cleanup_transfers()

    with lock:
        if not paired_session(token):
            return jsonify({"error": "Device is not paired."}), 403

        transfer = transfers.get(transfer_id)

        if not transfer or transfer["pair_token"] != token:
            return jsonify({"error": "Transfer not found or expired."}), 404

        if transfer["status"] != "approved":
            return jsonify({
                "error": "The recipient has not approved this file."
            }), 403

        path = transfer["path"]
        filename = transfer["filename"]

        if not os.path.isfile(path):
            transfers.pop(transfer_id, None)
            return jsonify({"error": "File is no longer available."}), 404

    return send_file(
        path,
        as_attachment=True,
        download_name=filename + ".tbenc",
        mimetype="application/octet-stream",
    )


@app.errorhandler(413)
def too_large(_error):
    return jsonify({
        "error": "Encrypted upload too large. Original files are limited to 10 MB."
    }), 413


if __name__ == "__main__":
    print(f"TrustBridge public URL: {PUBLIC_URL}")
    print("Original file limit: 10 MB")
    print("Encrypted server-side storage enabled")
    app.run(host="0.0.0.0", port=5000, debug=False)

