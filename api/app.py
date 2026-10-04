"""
Render pe deploy karne wali API
-------------------------------
Environment Variables (Render Dashboard se set karo):

ENCODER_SECRET = shibu123
ADMIN_KEY      = koi_strong_admin_key_rakho
"""

from flask import Flask, request, jsonify
import os
import hashlib
import time
from functools import wraps

app = Flask(__name__)

# ========== Environment Variables ==========
ENCODER_SECRET = "shibu123"
ADMIN_KEY = shibu1234
# Simple in-memory storage (Render free tier pe restart hone pe data urrega)
# Production mein PostgreSQL / Redis use karna better hai
# Format: { file_id: { "password_hash": "...", "original_name": "...", "created_at": 123 } }
FILES_DB = {}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Python File Protector API",
        "endpoints": ["/register", "/verify", "/stats"]
    })


@app.route("/register", methods=["POST"])
def register():
    """Encoder se naya file register hota hai"""
    data = request.json or {}

    secret = data.get("secret")
    file_id = data.get("file_id")
    password = data.get("password")
    original_name = data.get("original_name", "unknown.py")

    if secret != ENCODER_SECRET:
        return jsonify({"success": False, "error": "Invalid encoder secret"}), 403

    if not file_id or not password:
        return jsonify({"success": False, "error": "Missing fields"}), 400

    if file_id in FILES_DB:
        return jsonify({"success": False, "error": "File ID already exists"}), 400

    FILES_DB[file_id] = {
        "password_hash": hash_password(password),
        "original_name": original_name,
        "created_at": int(time.time()),
        "runs": 0
    }

    return jsonify({
        "success": True,
        "message": "File registered successfully",
        "file_id": file_id
    })


@app.route("/verify", methods=["POST"])
def verify():
    """Protected file se password verify hota hai"""
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

    # Success
    record["runs"] += 1
    return jsonify({
        "success": True,
        "message": "Password correct"
    })


@app.route("/stats", methods=["GET"])
def stats():
    """Kitne files registered hain (optional)"""
    key = request.args.get("key")
    if key != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify({
        "total_files": len(FILES_DB),
        "files": [
            {
                "file_id": fid,
                "original_name": info["original_name"],
                "runs": info["runs"],
                "created_at": info["created_at"]
            }
            for fid, info in FILES_DB.items()
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
