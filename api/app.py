"""
Server-Side Code Executor
Original code yahan encrypted rehta hai aur yahi pe chalta hai.
"""

from flask import Flask, request, jsonify
import os
import hashlib
import time
import base64
import io
import sys
import traceback
from contextlib import redirect_stdout, redirect_stderr
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)

ENCODER_SECRET = "SHAURYA"
ADMIN_KEY = "shibu"

# { file_id: {password_hash, salt, encrypted, original_name, created_at, runs} }
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


def safe_execute(code: str, inputs: list) -> tuple[bool, str]:
    """
    Code ko server pe chalata hai.
    input() ko pre-loaded values se replace karta hai.
    print() ka output capture karta hai.
    OSINT tool ke liye zaroori modules allow kiye gaye hain.
    """
    import json as _json
    import re as _re
    import time as _time
    import base64 as _base64
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
    from datetime import datetime as _datetime

    input_iter = iter(inputs)

    def fake_input(prompt=""):
        try:
            value = next(input_iter)
            print(prompt + str(value))
            return value
        except StopIteration:
            return ""

    # File save ko soft disable (Render pe file user ko nahi milti)
    def fake_open(*args, **kwargs):
        raise PermissionError("File saving is disabled on server. Use option [3] to print Base64 instead.")

    safe_builtins = {
        "print": print,
        "input": fake_input,
        "open": fake_open,
        "range": range,
        "len": len,
        "str": str,
        "int": int,
        "float": float,
        "list": list,
        "dict": dict,
        "tuple": tuple,
        "set": set,
        "bool": bool,
        "abs": abs,
        "round": round,
        "min": min,
        "max": max,
        "sum": sum,
        "sorted": sorted,
        "enumerate": enumerate,
        "zip": zip,
        "map": map,
        "filter": filter,
        "type": type,
        "isinstance": isinstance,
        "True": True,
        "False": False,
        "None": None,
        "Exception": Exception,
        "__import__": __import__,
    }

    # Modules jo script use karti hai
    safe_globals = {
        "__builtins__": safe_builtins,
        "sys": sys,
        "json": _json,
        "re": _re,
        "time": _time,
        "base64": _base64,
        "datetime": type("datetime", (), {"datetime": _datetime})(),
        "urllib": type("urllib", (), {
            "request": _urllib_request,
            "error": _urllib_error
        })(),
    }

    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()

    try:
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            exec(code, safe_globals, {})
        output = stdout_capture.getvalue()
        errors = stderr_capture.getvalue()
        if errors:
            output += "\n[Errors]\n" + errors
        return True, output
    except Exception:
        error_msg = traceback.format_exc()
        return False, error_msg


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "service": "Server-Side Python Executor",
        "version": "3.0"
    })


@app.route("/register", methods=["POST"])
def register():
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

    FILES_DB[file_id] = {
        "password_hash": hash_password(password),
        "salt": salt_b64,
        "encrypted": encrypted,
        "original_name": original_name,
        "created_at": int(time.time()),
        "runs": 0
    }

    return jsonify({"success": True, "file_id": file_id})


@app.route("/verify", methods=["POST"])
def verify():
    data = request.json or {}
    file_id = data.get("file_id")
    password = data.get("password")

    record = FILES_DB.get(file_id)
    if not record:
        return jsonify({"success": False, "error": "File not found"}), 404

    if record["password_hash"] != hash_password(password):
        return jsonify({"success": False, "error": "Wrong password"}), 401

    return jsonify({"success": True})


@app.route("/execute", methods=["POST"])
def execute():
    data = request.json or {}
    file_id = data.get("file_id")
    password = data.get("password")
    inputs = data.get("inputs", [])

    record = FILES_DB.get(file_id)
    if not record:
        return jsonify({"success": False, "error": "File not found"}), 404

    if record["password_hash"] != hash_password(password):
        return jsonify({"success": False, "error": "Wrong password"}), 401

    # Decrypt
    try:
        salt = base64.b64decode(record["salt"])
        key = derive_key(password, salt)
        f = Fernet(key)
        code = f.decrypt(record["encrypted"].encode()).decode()
    except Exception:
        return jsonify({"success": False, "error": "Decryption failed"}), 500

    # Execute on server
    success, output = safe_execute(code, inputs)

    record["runs"] += 1

    if success:
        return jsonify({"success": True, "output": output})
    else:
        return jsonify({"success": False, "error": output})


@app.route("/stats")
def stats():
    if request.args.get("key") != ADMIN_KEY:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify({
        "total_files": len(FILES_DB),
        "files": [
            {"name": v["original_name"], "runs": v["runs"]}
            for v in FILES_DB.values()
        ]
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
