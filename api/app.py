"""
Render API - Strong Version
Encrypted code yahan store hota hai.
Password sahi hone par hi code return hota hai.
"""

from flask import Flask, request, jsonify
import os
import hashlib
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)

# ========== Environment Variables ==========
ENCODER_SECRET = "shaurya"
ADMIN_KEY = "shibu"

# In-memory DB (Render restart pe data urrega - free tier limitation)
# Format: { file_id: {password_hash, salt, encrypted, original_name, created_at, runs} }
FILES_DB = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Strong Python Protector API",
        "version": "2.0"
    })


@app.route("/register", methods=["POST"])
def register():
    """Encoder se naya file + encrypted code register hota hai"""
    data = request.json or {}

    if data.get("secret") != ENCODER_SECRET:
        return jsonify({"success": False, "error": "Invalid encoder secret"}), 403

    file_id = data.get("file_id")
    password = data.get("password")
    salt_b64 = data.get("salt")
    encrypted = data.get("encrypted")
    original_name = data.get("original_name", "unknown.py")

    if not all([file_id, password, salt_b64, encrypted]):
        return jsonify({"success": False, "error": "Missing fields"}), 400

    if file_id in FILES_DB:
        return jsonify({"success": False, "error": "File ID already exists"}), 400

    FILES_DB[file_id] = {
        "password_hash": hash_password(password),
        "salt": salt_b64,
        "encrypted": encrypted,
        "original_name": original_name,
        "created_at": int(time.time()),
        "runs": 0
    }

    return jsonify({
        "success": True,
        "message": "File registered",
        "file_id": file_id
    })


@app.route("/run", methods=["POST"])
def run_file():
    """Password verify karke decrypted code return karta hai"""
    data = request.json or {}

    file_id = data.get("file_id")
    password = data.get("password")

    if not file_id or not password:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    record = FILES_DB.get(file_id)
    if not record:
        return jsonify({"success": False, "error": "File not found"}), 404

    if record["password_hash"] != hash_password(password):
        return jsonify({"success": False, "error": "Wrong password"}), 401

    # Password sahi hai → decrypt karke code bhejo
    try:
        salt = base64.b64decode(record["salt"])
        key = derive_key(password, salt)
        f = Fernet(key)
        code = f.decrypt(record["encrypted"].encode()).decode()
    except Exception:
        return jsonify({"success": False, "error": "Decryption failed"}), 500

    record["runs"] += 1

    return jsonify({
        "success": True,
        "code": code
    })


@app.route("/stats", methods=["GET"])
def stats():
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({
        "total_files": len(FILES_DB),
        "files": [
            {
                "file_id": fid[:8] + "...",
                "original_name": info["original_name"],
                "runs": info["runs"]
            }
            for fid, info in FILES_DB.items()
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
